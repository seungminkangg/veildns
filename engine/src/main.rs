use std::{
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
};

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use veildns_engine::{
    BoxError,
    config::Config,
    proxy::{self, Metrics},
};

const HELP: &str = "VeilDNS Engine — local encrypted-DNS proxy\n\nUsage:\n  veildns-engine --config PATH [--exit-on-stdin-close]\n  veildns-engine --check-config PATH\n  veildns-engine --help\n  veildns-engine --version\n\nBinds only 127.0.0.1. Config is strict JSON; see config.example.json.\nEvents are JSON lines on stdout. No domains or traffic contents are logged.\nCtrl-C or SIGTERM closes the listener and active connections.\n--exit-on-stdin-close also stops when the parent closes its dedicated stdin pipe.\n";

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        // Error chains can contain request URLs or private file paths: never print them.
        println!(
            "{}",
            serde_json::json!({"event":"error","code":"startup_failed","message":"Check configuration, port availability, and engine permissions"})
        );
        std::process::exit(1);
    }
}

async fn run() -> Result<(), BoxError> {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    let exit_on_stdin_close = args
        .iter()
        .position(|arg| arg == "--exit-on-stdin-close")
        .map(|index| args.remove(index))
        .is_some();
    match args.as_slice() {
        [arg] if !exit_on_stdin_close && (arg == "--help" || arg == "-h") => {
            print!("{HELP}");
            return Ok(());
        }
        [arg] if !exit_on_stdin_close && (arg == "--version" || arg == "-V") => {
            println!("veildns-engine {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        [arg, path] if !exit_on_stdin_close && arg == "--check-config" => {
            let _ = Config::load(&PathBuf::from(path))?;
            println!("{}", serde_json::json!({"event":"config_valid"}));
            return Ok(());
        }
        [arg, _] if arg == "--config" => {}
        _ => {
            eprint!("{HELP}");
            return Err(std::io::Error::other("invalid arguments").into());
        }
    }
    let config = Config::load(&PathBuf::from(&args[1]))?;
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, config.listen_port)).await?;
    let shutdown = CancellationToken::new();
    if exit_on_stdin_close {
        let stop = shutdown.clone();
        // Tokio's stdin uses an uncancellable blocking-pool task, which can prevent
        // runtime shutdown while stdin remains open. A detached OS thread avoids that.
        std::thread::Builder::new()
            .name("parent-lifetime".into())
            .spawn(move || {
                use std::io::Read;
                let mut stdin = std::io::stdin().lock();
                let mut buffer = [0; 256];
                loop {
                    match stdin.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                stop.cancel();
            })?;
    }
    let metrics = Arc::new(Metrics::default());
    let stop = shutdown.clone();
    let signal_task = tokio::spawn(async move {
        #[cfg(unix)]
        {
            if let Ok(mut terminate) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        stop.cancel();
    });
    let result = proxy::serve(listener, config, shutdown.clone(), metrics.clone()).await;
    shutdown.cancel();
    signal_task.abort();
    println!(
        "{}",
        serde_json::json!({"event":"stopped", "requests":metrics.requests.load(Ordering::Relaxed), "tunnels":metrics.tunnels.load(Ordering::Relaxed), "fragmented":metrics.fragmented.load(Ordering::Relaxed), "errors":metrics.errors.load(Ordering::Relaxed)})
    );
    result
}
