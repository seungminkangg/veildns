# Contributing

Keep changes scoped and explain the user-visible problem. Do not copy SecretDNS
code, binaries, logos, domain lists, or other assets without a compatible license.

Before opening a pull request:

```bash
cargo fmt --manifest-path engine/Cargo.toml --check
cargo clippy --manifest-path engine/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path engine/Cargo.toml --locked
swift test --package-path macos
bash scripts/build-macos.sh
python3 scripts/smoke-proxy.py build/VeilDNS.app/Contents/Resources/veildns-engine
```

Parser changes need malformed/truncated-input and byte-preservation coverage.
Proxy lifecycle changes need restore, conflict, failure, and crash-path coverage.
Preserve loopback-only binding, certificate verification, bounded resources,
end-to-end TLS, and the separation between user and privileged processes.

Never claim complete traffic protection or ISP bypass from parser tests or a
successful public-site fetch. Do not place browsing history, credentials, machine
identifiers, signing keys, or private network information in issues or artifacts.

Use an intent-based commit subject; useful trailers include `Tested:`,
`Constraint:`, `Rejected:`, and `Not-tested:`.
