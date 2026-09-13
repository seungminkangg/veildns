use std::{
    convert::Infallible,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{HOST, HeaderMap, HeaderName, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    time::{Instant, Sleep, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    BoxError,
    config::{Config, normalize_domain},
    dns::{DohResolver, is_public},
    error,
    tls::{self, Inspection},
};

const MAX_CLIENTS: usize = 128;
const MAX_TUNNELS: usize = 256;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub tunnels: AtomicU64,
    pub fragmented: AtomicU64,
    pub errors: AtomicU64,
}

struct State {
    config: Config,
    dns: DohResolver,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    tunnels: Arc<Semaphore>,
    metrics: Arc<Metrics>,
}

/// Serve only a loopback listener. Cancellation closes clients, tunnels, and the listener.
pub async fn serve(
    listener: TcpListener,
    config: Config,
    shutdown: CancellationToken,
    metrics: Arc<Metrics>,
) -> Result<(), BoxError> {
    if listener.local_addr()?.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(error("proxy listener must bind to 127.0.0.1"));
    }
    let mut config = config;
    config.validate()?;
    let tasks = TaskTracker::new();
    let state = Arc::new(State {
        dns: DohResolver::new(config.resolver)?,
        config,
        shutdown: shutdown.clone(),
        tasks: tasks.clone(),
        tunnels: Arc::new(Semaphore::new(MAX_TUNNELS)),
        metrics,
    });
    let clients = Arc::new(Semaphore::new(MAX_CLIENTS));
    if !shutdown.is_cancelled() {
        println!(
            "{}",
            serde_json::json!({"event":"ready","listen":listener.local_addr()?.to_string()})
        );
    }
    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let (socket, peer) = accepted?;
                if !peer.ip().is_loopback() { continue; }
                let Ok(permit) = clients.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                let stop = shutdown.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = socket.set_nodelay(true);
                    let io = TokioIo::new(IdleIo::new(socket));
                    let service = service_fn(move |request| handle(request, state.clone()));
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_headers(64).max_buf_size(32 * 1024).half_close(true);
                    let connection = builder.serve_connection(io, service).with_upgrades();
                    tokio::select! {
                        _ = stop.cancelled() => {},
                        _ = connection => {},
                    }
                });
            }
        }
    }
    drop(listener);
    tasks.close();
    tasks.wait().await;
    Ok(())
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<ProxyBody>, Infallible> {
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    // Hyper's read buffer limit bounds incomplete parsing, but a complete header
    // can arrive in an already allocated buffer. Enforce a forwarding limit too.
    let header_bytes = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len() + 4)
        .sum::<usize>();
    if request.uri().to_string().len() > 8192 || header_bytes > 32 * 1024 {
        state.metrics.errors.fetch_add(1, Ordering::Relaxed);
        return Ok(response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "Proxy request headers are too large\n",
        ));
    }
    let result = if request.method() == hyper::Method::CONNECT {
        connect(request, state.clone()).await
    } else {
        forward(request, state.clone()).await
    };
    Ok(match result {
        Ok(response) => response,
        Err(status) => {
            state.metrics.errors.fetch_add(1, Ordering::Relaxed);
            response(
                status,
                match status {
                    StatusCode::BAD_REQUEST => "Invalid proxy request\n",
                    StatusCode::FORBIDDEN => "Destination is blocked by local network policy\n",
                    StatusCode::SERVICE_UNAVAILABLE => "Proxy connection limit reached\n",
                    _ => "Upstream connection failed\n",
                },
            )
        }
    })
}

fn response(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("connection", "close")
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("static response")
}

#[derive(Debug, PartialEq, Eq)]
struct Destination {
    host: String,
    port: u16,
}

fn destination(authority: &str, default_port: Option<u16>) -> Result<Destination, StatusCode> {
    if authority.is_empty()
        || !authority.is_ascii()
        || authority.bytes().any(|b| {
            b.is_ascii_whitespace() || matches!(b, b'@' | b'/' | b'\\' | b'#' | b'?' | b'%')
        })
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let authority: hyper::http::uri::Authority =
        authority.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    let raw_host = authority.host();
    let host = raw_host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw_host);
    let host = if let Ok(ip) = host.parse::<IpAddr>() {
        ip.to_string()
    } else {
        normalize_domain(host).map_err(|_| StatusCode::BAD_REQUEST)?
    };
    // Invalid/empty/overflowing explicit ports must never fall back to a default.
    let explicit_port = if raw_host.starts_with('[') {
        authority
            .as_str()
            .get(raw_host.len()..)
            .is_some_and(|s| s.starts_with(':'))
    } else {
        authority.as_str().contains(':')
    };
    let port = if explicit_port {
        authority.port_u16().ok_or(StatusCode::BAD_REQUEST)?
    } else {
        default_port.ok_or(StatusCode::BAD_REQUEST)?
    };
    if port == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(Destination { host, port })
}

fn validate_host(
    headers: &HeaderMap,
    dest: &Destination,
    default_port: Option<u16>,
) -> Result<(), StatusCode> {
    let mut hosts = headers.get_all(HOST).iter();
    let host = hosts.next().ok_or(StatusCode::BAD_REQUEST)?;
    if hosts.next().is_some()
        || destination(
            host.to_str().map_err(|_| StatusCode::BAD_REQUEST)?,
            default_port,
        )? != *dest
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

async fn open_upstream(dest: &Destination, state: &State) -> Result<TcpStream, StatusCode> {
    let addresses = state
        .dns
        .resolve(&dest.host)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let addresses: Vec<_> = addresses
        .into_iter()
        .filter(|ip| state.config.allow_private || is_public(*ip))
        .collect();
    if addresses.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }
    // The address passed to connect is the checked DoH result, with no second DNS lookup.
    let connection = async {
        for ip in addresses.into_iter().take(16) {
            if let Ok(Ok(stream)) = timeout(
                Duration::from_secs(3),
                TcpStream::connect(SocketAddr::new(ip, dest.port)),
            )
            .await
            {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
        }
        Err(StatusCode::BAD_GATEWAY)
    };
    timeout(CONNECT_TIMEOUT, connection)
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
}

async fn connect(
    mut request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<ProxyBody>, StatusCode> {
    if request.uri().scheme().is_some() || request.uri().path_and_query().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let dest = destination(
        request
            .uri()
            .authority()
            .ok_or(StatusCode::BAD_REQUEST)?
            .as_str(),
        None,
    )?;
    validate_host(request.headers(), &dest, None)?;
    if request.headers().contains_key("transfer-encoding")
        || request
            .headers()
            .get("content-length")
            .is_some_and(|v| v != "0")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let permit = state
        .tunnels
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let upstream = open_upstream(&dest, &state).await?;
    let on_upgrade = hyper::upgrade::on(&mut request);
    let task_state = state.clone();
    state.tasks.spawn(async move {
        let _permit = permit;
        let future = async {
            let upgraded = timeout(Duration::from_secs(10), on_upgrade).await.map_err(|_| error("upgrade timeout"))??;
            task_state.metrics.tunnels.fetch_add(1, Ordering::Relaxed);
            let mut client = TokioIo::new(upgraded);
            let mut upstream = IdleIo::new(upstream);
            if task_state.config.needs_inspection(&dest.host) {
                inspect_and_forward(&mut client, &mut upstream, &dest.host, &task_state).await?;
            }
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
            Ok::<(), BoxError>(())
        };
        tokio::select! {
            _ = task_state.shutdown.cancelled() => {},
            result = future => { if result.is_err() { task_state.metrics.errors.fetch_add(1, Ordering::Relaxed); } },
        }
    });
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(
            Full::new(Bytes::new())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("static CONNECT response"))
}

async fn inspect_and_forward<C: AsyncRead + Unpin, U: AsyncWrite + Unpin>(
    client: &mut C,
    upstream: &mut U,
    host: &str,
    state: &State,
) -> Result<(), BoxError> {
    let mut buffered = Vec::new();
    let inspect = async {
        let mut chunk = [0; 4096];
        loop {
            let inspection = tls::inspect(&buffered);
            if inspection != Inspection::NeedMore {
                return Ok::<_, BoxError>(inspection);
            }
            let available = (tls::MAX_INSPECTION_BYTES - buffered.len()).min(chunk.len());
            if available == 0 {
                return Ok(Inspection::Passthrough);
            }
            let n = client.read(&mut chunk[..available]).await?;
            if n == 0 {
                return Ok(Inspection::Passthrough);
            }
            buffered.extend_from_slice(&chunk[..n]);
        }
    };
    let inspection = match timeout(Duration::from_secs(3), inspect).await {
        Ok(result) => result?,
        Err(_) => Inspection::Passthrough,
    };
    if let Inspection::ClientHello {
        server_name,
        record_start,
        split_offset,
    } = inspection
        && state.config.should_fragment(host, &server_name)
        && let Some((first, second)) = tls::split_record(&buffered, record_start, split_offset)
    {
        upstream.write_all(&first).await?;
        upstream.flush().await?;
        tokio::time::sleep(Duration::from_millis(state.config.fragment_delay_ms)).await;
        upstream.write_all(&second).await?;
        state.metrics.fragmented.fetch_add(1, Ordering::Relaxed);
    } else {
        upstream.write_all(&buffered).await?;
    }
    Ok(())
}

async fn forward(
    mut request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<ProxyBody>, StatusCode> {
    if request.uri().scheme_str() != Some("http") || request.headers().contains_key("upgrade") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let dest = destination(
        request
            .uri()
            .authority()
            .ok_or(StatusCode::BAD_REQUEST)?
            .as_str(),
        Some(80),
    )?;
    validate_host(request.headers(), &dest, Some(80))?;
    sanitize_headers(request.headers_mut())?;
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .parse::<Uri>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    request
        .headers_mut()
        .insert("connection", HeaderValue::from_static("close"));
    let request = request.map(clean_body);
    let stream = open_upstream(&dest, &state).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(IdleIo::new(stream)))
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let stop = state.shutdown.clone();
    state.tasks.spawn(async move {
        tokio::select! { _ = stop.cancelled() => {}, _ = connection => {} }
    });
    let mut response = timeout(Duration::from_secs(30), sender.send_request(request))
        .await
        .map_err(|_| StatusCode::GATEWAY_TIMEOUT)?
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    sanitize_headers(response.headers_mut()).map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(response.map(clean_body))
}

fn clean_body(body: Incoming) -> ProxyBody {
    body.map_frame(|mut frame| {
        if let Some(trailers) = frame.trailers_mut()
            && sanitize_headers(trailers).is_err()
        {
            // Invalid hop-by-hop trailer metadata is never forwarded.
            trailers.clear();
        }
        frame
    })
    .map_err(|error| -> BoxError { Box::new(error) })
    .boxed_unsync()
}

fn sanitize_headers(headers: &mut HeaderMap) -> Result<(), StatusCode> {
    let mut nominated = Vec::new();
    for value in headers.get_all("connection") {
        for token in value
            .to_str()
            .map_err(|_| StatusCode::BAD_REQUEST)?
            .split(',')
        {
            let name = HeaderName::from_bytes(token.trim().as_bytes())
                .map_err(|_| StatusCode::BAD_REQUEST)?;
            if matches!(
                name.as_str(),
                "host" | "content-length" | "transfer-encoding"
            ) {
                return Err(StatusCode::BAD_REQUEST);
            }
            nominated.push(name);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    Ok(())
}

/// A shared read/write inactivity deadline; a long active download is not timed out.
struct IdleIo<T> {
    inner: T,
    deadline: Pin<Box<Sleep>>,
}

impl<T> IdleIo<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep(IDLE_TIMEOUT)),
        }
    }
    fn touch(&mut self) {
        self.deadline.as_mut().reset(Instant::now() + IDLE_TIMEOUT);
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if self.deadline.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection idle timeout",
            ))
        } else {
            Ok(())
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check(cx)?;
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch();
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check(cx)?;
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check(cx)?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_validation_rejects_ambiguous_and_hostile_targets() {
        for bad in [
            "example.com:0",
            "example.com:",
            "example.com:65536",
            "a@b:443",
            "a/b:443",
            "a%2eb:443",
            "a\\b:443",
            "a b:443",
            "a#b:443",
            "[::1%lo0]:443",
        ] {
            assert!(destination(bad, Some(80)).is_err(), "{bad}");
        }
        assert_eq!(
            destination("[::1]:443", None).unwrap(),
            Destination {
                host: "::1".into(),
                port: 443
            }
        );
        assert_eq!(
            destination("EXAMPLE.COM.:80", None).unwrap(),
            Destination {
                host: "example.com".into(),
                port: 80
            }
        );
        assert!(destination("example.com", None).is_err());
    }

    #[test]
    fn strips_proxy_credentials_and_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "proxy-authorization",
            HeaderValue::from_static("Basic secret"),
        );
        headers.insert(
            "connection",
            HeaderValue::from_static("X-Private, keep-alive"),
        );
        headers.insert("x-private", HeaderValue::from_static("private"));
        headers.insert("host", HeaderValue::from_static("example.com"));
        sanitize_headers(&mut headers).unwrap();
        assert_eq!(headers.len(), 1);
        headers.insert("connection", HeaderValue::from_static("content-length"));
        assert!(sanitize_headers(&mut headers).is_err());
    }
}
