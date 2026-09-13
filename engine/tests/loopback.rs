use std::{
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use veildns_engine::{
    config::{Config, Fragmentation},
    proxy::{self, Metrics},
};

async fn proxy(config: Config) -> (SocketAddr, CancellationToken, JoinHandle<()>, Arc<Metrics>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let metrics = Arc::new(Metrics::default());
    let counts = metrics.clone();
    let task = tokio::spawn(async move {
        proxy::serve(listener, config, shutdown, counts)
            .await
            .unwrap();
    });
    (addr, stop, task, metrics)
}

async fn header(stream: &mut TcpStream) -> String {
    timeout(Duration::from_secs(5), async {
        let mut data = Vec::new();
        let mut byte = [0];
        while !data.ends_with(b"\r\n\r\n") {
            assert!(data.len() < 64 * 1024);
            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
            data.push(byte[0]);
        }
        String::from_utf8(data).unwrap()
    })
    .await
    .unwrap()
}

async fn tunnel(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    assert!(header(&mut stream).await.starts_with("HTTP/1.1 200"));
    stream
}

async fn stop_proxy(stop: CancellationToken, task: JoinHandle<()>) {
    stop.cancel();
    timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn connect_echo_preserves_bytes_and_shutdown_releases_listener() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let (mut reader, mut writer) = stream.split();
        let _ = tokio::io::copy(&mut reader, &mut writer).await;
    });
    let (address, stop, task, metrics) = proxy(Config {
        allow_private: true,
        fragmentation: Fragmentation::Off,
        ..Config::default()
    })
    .await;
    let mut stream = tunnel(address, target).await;
    let data: Vec<u8> = (0..16384).map(|n| (n % 256) as u8).collect();
    stream.write_all(&data).await.unwrap();
    let mut received = vec![0; data.len()];
    timeout(Duration::from_secs(3), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, data);
    stop_proxy(stop, task).await;
    assert_eq!(metrics.tunnels.load(Ordering::Relaxed), 1);
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    let rebound = TcpListener::bind(address).await.unwrap();
    drop(rebound);
    timeout(Duration::from_secs(3), echo)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn forwards_absolute_http_and_strips_proxy_credentials() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let head = header(&mut stream).await;
        assert!(head.starts_with("POST /submit?x=1 HTTP/1.1\r\n"));
        assert!(!head.to_lowercase().contains("proxy-authorization"));
        assert!(!head.to_lowercase().contains("proxy-connection"));
        assert!(!head.to_lowercase().contains("x-hop"));
        let mut body = [0; 4];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"test");
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .unwrap();
    });
    let (address, stop, task, _) = proxy(Config {
        allow_private: true,
        ..Config::default()
    })
    .await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("POST http://{target}/submit?x=1 HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\nProxy-Authorization: Basic secret\r\nProxy-Connection: keep-alive\r\nConnection: close, x-hop\r\nX-Hop: secret\r\n\r\ntest").as_bytes()).await.unwrap();
    assert!(header(&mut stream).await.starts_with("HTTP/1.1 200"));
    let mut body = [0; 5];
    stream.read_exact(&mut body).await.unwrap();
    assert_eq!(&body, b"hello");
    upstream.await.unwrap();
    stop_proxy(stop, task).await;
}

#[tokio::test]
async fn rejects_private_destination_and_mismatched_host_before_connecting() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let (address, stop, task, _) = proxy(Config::default()).await;
    for (request, status) in [
        (
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"),
            "403",
        ),
        (
            format!("GET http://{target}/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            "400",
        ),
        (
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nContent-Length: 4\r\n\r\ntest"),
            "400",
        ),
        (
            format!(
                "GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\nHost: evil.example\r\n\r\n"
            ),
            "400",
        ),
    ] {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        assert!(
            header(&mut stream)
                .await
                .starts_with(&format!("HTTP/1.1 {status}"))
        );
    }
    assert!(
        timeout(Duration::from_millis(50), server.accept())
            .await
            .is_err()
    );
    stop_proxy(stop, task).await;
}

fn client_hello(name: &str) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&((name.len() + 9) as u16).to_be_bytes());
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
    body.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(name.len() as u16).to_be_bytes());
    body.extend_from_slice(name.as_bytes());
    let mut handshake = vec![1, 0];
    handshake.extend_from_slice(&(body.len() as u16).to_be_bytes());
    handshake.extend(body);
    handshake
}

fn record(body: &[u8]) -> Vec<u8> {
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(body.len() as u16).to_be_bytes());
    record.extend_from_slice(body);
    record
}

#[tokio::test]
async fn fragments_sni_from_multiple_client_reads_and_tls_records_without_changing_handshake() {
    let hello = client_hello("www.example.com");
    let cut = hello.len() - 7;
    let wire = [record(&hello[..cut]), record(&hello[cut..])].concat();
    let expected = hello.clone();
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = server.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = server.accept().await.unwrap();
        let mut payload = Vec::new();
        let mut count = 0;
        while payload.len() < expected.len() {
            let mut header = [0; 5];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(header[0], 22);
            let mut body = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            stream.read_exact(&mut body).await.unwrap();
            payload.extend(body);
            count += 1;
        }
        assert_eq!(payload, expected);
        assert_eq!(count, 3);
        stream.write_all(b"ok").await.unwrap();
    });
    let (address, stop, task, metrics) = proxy(Config {
        allow_private: true,
        domains: vec!["*.example.com".into()],
        ..Config::default()
    })
    .await;
    let mut stream = tunnel(address, target).await;
    for chunk in wire.chunks(3) {
        stream.write_all(chunk).await.unwrap();
        tokio::task::yield_now().await;
    }
    let mut ack = [0; 2];
    timeout(Duration::from_secs(5), stream.read_exact(&mut ack))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&ack, b"ok");
    assert_eq!(metrics.fragmented.load(Ordering::Relaxed), 1);
    upstream.await.unwrap();
    stop_proxy(stop, task).await;
}
