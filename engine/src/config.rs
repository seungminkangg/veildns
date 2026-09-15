use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::Path};

use crate::{BoxError, error};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Resolver {
    Cloudflare,
    #[default]
    Google,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Fragmentation {
    Selected,
    #[default]
    All,
    Off,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen_port: u16,
    pub resolver: Resolver,
    pub fragmentation: Fragmentation,
    pub domains: Vec<String>,
    pub exclusions: Vec<String>,
    pub fragment_delay_ms: u64,
    pub allow_private: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 8080,
            resolver: Resolver::Google,
            fragmentation: Fragmentation::All,
            domains: Vec::new(),
            exclusions: Vec::new(),
            fragment_delay_ms: 5,
            allow_private: false,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, BoxError> {
        // Configuration contains no credentials, but cap input before allocating.
        if std::fs::metadata(path)?.len() > 256 * 1024 {
            return Err(error("configuration exceeds 256 KiB"));
        }
        let mut config: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&mut self) -> Result<(), BoxError> {
        if self.listen_port == 0 {
            return Err(error("listen_port must be between 1 and 65535"));
        }
        if self.fragment_delay_ms > 100 {
            return Err(error("fragment_delay_ms must be between 0 and 100"));
        }
        for patterns in [&mut self.domains, &mut self.exclusions] {
            if patterns.len() > 4096 {
                return Err(error("at most 4096 domain rules are allowed per list"));
            }
            for pattern in patterns.iter_mut() {
                let (prefix, host) = match pattern.strip_prefix("*.") {
                    Some(host) => ("*.", host),
                    None => ("", pattern.as_str()),
                };
                *pattern = format!("{prefix}{}", normalize_domain(host)?);
            }
            patterns.sort_unstable();
            patterns.dedup();
        }
        Ok(())
    }

    pub fn needs_inspection(&self, host: &str) -> bool {
        self.fragmentation != Fragmentation::Off
            && (self.fragmentation != Fragmentation::Selected || !self.domains.is_empty())
            && !self.exclusions.iter().any(|pattern| matches(pattern, host))
    }

    pub fn should_fragment(&self, host: &str, sni: &str) -> bool {
        if self.fragmentation == Fragmentation::Off
            || self
                .exclusions
                .iter()
                .any(|p| matches(p, host) || matches(p, sni))
        {
            return false;
        }
        self.fragmentation == Fragmentation::All || self.domains.iter().any(|p| matches(p, sni))
    }
}

pub fn normalize_domain(host: &str) -> Result<String, BoxError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok() {
        return Err(error("invalid DNS hostname (use ASCII or IDNA punycode)"));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(error("invalid DNS hostname (use ASCII or IDNA punycode)"));
        }
    }
    Ok(host.to_ascii_lowercase())
}

fn matches(pattern: &str, domain: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.len() > suffix.len() + 1
            && domain
                .get(domain.len() - suffix.len()..)
                .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
    } else {
        domain.eq_ignore_ascii_case(pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_rules_have_label_boundaries_and_exclusions_win() {
        let mut c = Config {
            fragmentation: Fragmentation::Selected,
            domains: vec!["*.Example.COM".into(), "example.org".into()],
            exclusions: vec!["safe.example.com".into()],
            ..Config::default()
        };
        c.validate().unwrap();
        assert!(c.should_fragment("example.com", "sub.example.com"));
        assert!(!c.should_fragment("example.com", "example.com"));
        assert!(!c.should_fragment("example.com", "badexample.com"));
        assert!(!c.should_fragment("safe.example.com", "sub.example.com"));
        assert!(!c.should_fragment("example.com", "safe.example.com"));
        assert!(c.should_fragment("example.org", "EXAMPLE.ORG"));
    }

    #[test]
    fn defaults_cover_every_https_connection_through_google() {
        let c = Config::default();
        assert_eq!(c.resolver, Resolver::Google);
        assert_eq!(c.fragmentation, Fragmentation::All);
        // An empty document must inherit the same defaults the app writes.
        assert_eq!(
            serde_json::from_str::<Config>("{}").unwrap().resolver,
            Resolver::Google
        );
        assert_eq!(
            serde_json::from_str::<Config>("{}").unwrap().fragmentation,
            Fragmentation::All
        );
        // Exclusions stay authoritative when every connection is eligible.
        let mut c = Config {
            exclusions: vec!["safe.example.com".into()],
            ..Config::default()
        };
        c.validate().unwrap();
        assert!(c.should_fragment("example.com", "example.com"));
        assert!(!c.should_fragment("safe.example.com", "safe.example.com"));
    }

    #[test]
    fn reject_invalid_config() {
        for bad in [
            "http://example.com",
            "a..b",
            "-a.com",
            "a_.com",
            "127.0.0.1",
            "é.com",
        ] {
            assert!(normalize_domain(bad).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<Config>(r#"{"unknown":true}"#).is_err());
        assert!(
            Config {
                listen_port: 0,
                ..Config::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Config {
                fragment_delay_ms: 101,
                ..Config::default()
            }
            .validate()
            .is_err()
        );
    }
}
