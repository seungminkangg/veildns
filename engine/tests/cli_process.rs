use std::{
    io::{BufRead, BufReader},
    net::TcpListener,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct ProcessGuard(Child);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn parent_stdin_eof_stops_process_and_releases_port() {
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let path = std::env::temp_dir().join(format!(
        "veildns-engine-{}-{}.json",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, format!(r#"{{"listen_port":{}}}"#, address.port())).unwrap();
    drop(reservation);
    let mut child = ProcessGuard(
        Command::new(env!("CARGO_BIN_EXE_veildns-engine"))
            .arg("--config")
            .arg(&path)
            .arg("--exit-on-stdin-close")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdin = child.0.stdin.take().unwrap();
    let stdout = child.0.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let event: serde_json::Value =
        serde_json::from_str(&receiver.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap();
    assert_eq!(event["event"], "ready");
    assert_eq!(event["listen"], address.to_string());
    drop(stdin);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "engine did not exit when its parent pipe closed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let event: serde_json::Value =
        serde_json::from_str(&receiver.recv_timeout(Duration::from_secs(2)).unwrap()).unwrap();
    assert_eq!(event["event"], "stopped");
    let _rebound = TcpListener::bind(address).unwrap();
    std::fs::remove_file(path).unwrap();
}
