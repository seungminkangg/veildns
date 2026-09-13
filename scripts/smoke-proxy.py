"""Real TLS/DoH integration; never changes system network settings.

Runs the engine on a temporary loopback port, then verifies public HTTPS through
the CONNECT tunnel with certificate checking and SNI fragmentation enabled.
Public resolver availability is deliberately a required check, not a silent skip.
"""
import argparse
import json
import pathlib
import queue
import socket
import ssl
import subprocess
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("engine", type=pathlib.Path)
    parser.add_argument("--resolver", choices=["cloudflare", "google"], default="cloudflare")
    args = parser.parse_args()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="veildns-smoke-") as directory:
        config = pathlib.Path(directory) / "config.json"
        config.write_text(json.dumps({
            "listen_port": port, "resolver": args.resolver, "fragmentation": "all",
            "domains": [], "exclusions": [], "fragment_delay_ms": 5, "allow_private": False,
        }), encoding="utf-8")
        subprocess.run([str(args.engine.resolve()), "--check-config", str(config)], check=True)
        process = subprocess.Popen([str(args.engine.resolve()), "--config", str(config), "--exit-on-stdin-close"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        output = queue.Queue()
        stopped = None
        def read_output():
            for line in process.stdout:
                output.put(line.rstrip())
        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + 20
            ready = False
            while time.monotonic() < deadline:
                try:
                    line = output.get(timeout=0.2)
                except queue.Empty:
                    if process.poll() is not None:
                        raise RuntimeError(f"Engine exited {process.returncode} before readiness")
                    continue
                print(line)
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "ready":
                    assert event["listen"] == f"127.0.0.1:{port}", event
                    ready = True
                    break
            if not ready:
                raise TimeoutError("Engine did not become ready")
            with socket.create_connection(("127.0.0.1", port), timeout=30) as tunnel:
                tunnel.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
                headers = b""
                while not headers.endswith(b"\r\n\r\n"):
                    chunk = tunnel.recv(1)
                    if not chunk or len(headers) >= 16384:
                        raise RuntimeError(f"Incomplete CONNECT response: {headers!r}")
                    headers += chunk
                assert headers.split(b"\r\n", 1)[0].split()[1] == b"200", headers
                with ssl.create_default_context().wrap_socket(tunnel, server_hostname="example.com") as tls:
                    tls.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                    response = b""
                    while len(response) < 1024 * 1024:
                        chunk = tls.recv(16384)
                        if not chunk:
                            break
                        response += chunk
                    assert response.startswith(b"HTTP/1.1 200"), response[:200]
                    assert b"Example Domain" in response, response[:200]
                    print(json.dumps({"smoke": "passed", "resolver": args.resolver,
                                      "tls": tls.version(), "bytes_received": len(response)}))
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=2)
            while not output.empty():
                line = output.get_nowait()
                print(line)
                try:
                    event = json.loads(line)
                    if event.get("event") == "stopped":
                        stopped = event
                except json.JSONDecodeError:
                    pass
        assert process.returncode == 0, "Engine did not exit cleanly after stdin EOF"
        assert stopped is not None and stopped["fragmented"] >= 1, "No SNI fragmentation was reported for the real TLS handshake"


if __name__ == "__main__":
    main()
