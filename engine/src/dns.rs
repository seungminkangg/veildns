use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use reqwest::dns::{Name, Resolve, Resolving};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::{
    BoxError,
    config::{Resolver, normalize_domain},
    error,
};

const MAX_RESPONSE: usize = 64 * 1024;
const MAX_CACHE: usize = 1024;

struct NoSystemDns;
impl Resolve for NoSystemDns {
    fn resolve(&self, _name: Name) -> Resolving {
        Box::pin(async { Err(error("system DNS fallback is disabled")) })
    }
}

struct Cached {
    addresses: Vec<IpAddr>,
    expires: Instant,
}

pub struct DohResolver {
    client: reqwest::Client,
    endpoint: &'static str,
    cache: Mutex<HashMap<String, Cached>>,
}

#[derive(Debug, Deserialize)]
struct DnsResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "TC", default)]
    truncated: bool,
    #[serde(rename = "Question")]
    question: Vec<Question>,
    #[serde(rename = "Answer", default)]
    answers: Vec<Answer>,
}

#[derive(Debug, Deserialize)]
struct Question {
    name: String,
    #[serde(rename = "type")]
    kind: u16,
}

#[derive(Debug, Deserialize)]
struct Answer {
    name: String,
    #[serde(rename = "type")]
    kind: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

impl DohResolver {
    pub fn new(provider: Resolver) -> Result<Self, BoxError> {
        let (domain, bootstrap, endpoint) = match provider {
            Resolver::Cloudflare => (
                "cloudflare-dns.com",
                Ipv4Addr::new(1, 1, 1, 1),
                "https://cloudflare-dns.com/dns-query",
            ),
            Resolver::Google => (
                "dns.google",
                Ipv4Addr::new(8, 8, 8, 8),
                "https://dns.google/resolve",
            ),
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .tls_sslkeylogfile(false)
            .dns_resolver(Arc::new(NoSystemDns))
            .resolve(domain, SocketAddr::new(bootstrap.into(), 443))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(8))
            .pool_max_idle_per_host(2)
            .build()?;
        Ok(Self {
            client,
            endpoint,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub async fn resolve(&self, hostname: &str) -> Result<Vec<IpAddr>, BoxError> {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let hostname = normalize_domain(hostname)?;
        if let Some(cached) = self.cache.lock().await.get(&hostname)
            && cached.expires > Instant::now()
        {
            return Ok(cached.addresses.clone());
        }
        let (a, aaaa) = tokio::join!(self.query(&hostname, 1), self.query(&hostname, 28));
        let mut addresses = Vec::new();
        let mut ttl = 300;
        // A working address family remains usable if the other query fails.
        for (ips, record_ttl) in [a, aaaa].into_iter().flatten() {
            addresses.extend(ips);
            ttl = ttl.min(record_ttl);
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(error("encrypted DNS returned no usable addresses"));
        }
        if ttl > 0 {
            let mut cache = self.cache.lock().await;
            cache.retain(|_, entry| entry.expires > Instant::now());
            if cache.len() >= MAX_CACHE {
                cache.clear();
            }
            cache.insert(
                hostname,
                Cached {
                    addresses: addresses.clone(),
                    expires: Instant::now() + Duration::from_secs(ttl.into()),
                },
            );
        }
        Ok(addresses)
    }

    async fn query(&self, hostname: &str, kind: u16) -> Result<(Vec<IpAddr>, u32), BoxError> {
        let mut response = self
            .client
            .get(self.endpoint)
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .query(&[("name", hostname), ("type", &kind.to_string())])
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE as u64)
        {
            return Err(error("encrypted DNS response is too large"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if bytes.len() + chunk.len() > MAX_RESPONSE {
                return Err(error("encrypted DNS response is too large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        parse_response(&bytes, hostname, kind)
    }
}

fn parse_response(bytes: &[u8], hostname: &str, kind: u16) -> Result<(Vec<IpAddr>, u32), BoxError> {
    let response: DnsResponse = serde_json::from_slice(bytes)?;
    if response.status != 0
        || response.truncated
        || response.question.len() != 1
        || response.question[0].kind != kind
        || normalize_domain(&response.question[0].name)? != hostname
        || response.answers.len() > 128
    {
        return Err(error("invalid or unsuccessful encrypted DNS response"));
    }
    let mut canonical = hostname.to_owned();
    let mut names = HashSet::new();
    let mut ttl = 300;
    // Only addresses at the end of the requested CNAME chain are accepted.
    for _ in 0..16 {
        if !names.insert(canonical.clone()) {
            return Err(error("encrypted DNS CNAME cycle"));
        }
        let aliases: Vec<_> = response
            .answers
            .iter()
            .filter(|a| {
                a.kind == 5 && normalize_domain(&a.name).is_ok_and(|name| name == canonical)
            })
            .collect();
        if aliases.len() > 1 {
            return Err(error("ambiguous encrypted DNS CNAME response"));
        }
        if let Some(alias) = aliases.first() {
            canonical = normalize_domain(&alias.data)?;
            ttl = ttl.min(alias.ttl);
        } else {
            let mut ips = Vec::new();
            for answer in &response.answers {
                if answer.kind == kind && normalize_domain(&answer.name)? == canonical {
                    let ip = answer.data.parse::<IpAddr>()?;
                    if (kind == 1 && !ip.is_ipv4()) || (kind == 28 && !ip.is_ipv6()) {
                        return Err(error("encrypted DNS address type mismatch"));
                    }
                    ttl = ttl.min(answer.ttl);
                    ips.push(ip);
                }
            }
            return Ok((ips, ttl));
        }
    }
    Err(error("encrypted DNS CNAME chain exceeds limit"))
}

/// Conservative public routing policy; testing and private-network use require opt-in.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public(v4.into());
            }
            let s = ip.segments();
            // Global unicast only. Exclude documentation and transition mechanisms.
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
                && ip != Ipv6Addr::UNSPECIFIED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_question_type_chain_and_ignores_unrelated_addresses() {
        let response = br#"{"Status":0,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":5,"TTL":42,"data":"edge.example.com."},{"name":"edge.example.com.","type":1,"TTL":100,"data":"1.1.1.1"},{"name":"evil.com.","type":1,"TTL":0,"data":"127.0.0.1"}]}"#;
        let (ips, ttl) = parse_response(response, "example.com", 1).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        assert_eq!(ttl, 42);
        assert!(parse_response(response, "another.com", 1).is_err());
        assert!(parse_response(response, "example.com", 28).is_err());
    }

    #[test]
    fn reject_dns_error_truncation_and_cname_cycle() {
        for response in [
            r#"{"Status":3,"Question":[{"name":"example.com.","type":1}]}"#,
            r#"{"Status":0,"TC":true,"Question":[{"name":"example.com.","type":1}]}"#,
            r#"{"Status":0,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":5,"TTL":5,"data":"example.com."}]}"#,
        ] {
            assert!(parse_response(response.as_bytes(), "example.com", 1).is_err());
        }
    }

    #[test]
    fn rejects_private_reserved_and_transition_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.2.3",
            "192.168.0.1",
            "0.0.0.0",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }
}
