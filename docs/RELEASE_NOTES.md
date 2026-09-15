VeilDNS is an independent open-source macOS implementation inspired by SecretDNS's public feature descriptions.

**Changes in this preview**

- Defaults now target **Google · 8.8.8.8** for DNS over HTTPS and apply TLS ClientHello record fragmentation to **every HTTPS connection**. Both remain switchable in the app, and the exclusion list still wins over fragmentation.
- Administrator authorization is requested **once**. The first authorized run installs a launchd daemon, and later connections apply and restore proxy settings through a private UNIX socket without another password. **권한 유지 해제** in the app removes the daemon and the installed tool.

**Baseline**

- Native SwiftUI window and menu bar control, Korean interface, domain rules and resolver selection.
- Rust loopback HTTP/CONNECT proxy, DoH, selective TLS ClientHello SNI record fragmentation, no HTTPS interception.
- Scoped proxy changes with a recovery journal and a crash-recovery watcher.
- Separate Apple Silicon and Intel macOS packages, dependency license notices and SHA-256 checksums.

This is a **preview** for macOS 15+. Packages are **ad-hoc signed, not Apple-notarized**. Tests cover the protocol engine, app models, package launch, real HTTPS over the proxy and the privileged daemon lifecycle on CI; they do not prove compatibility with every browser, VPN, network or ISP. System-proxy-ignoring apps and UDP/QUIC are outside proxy coverage.

Because the daemon persists, code running as the installing account can change that account's scoped HTTP/HTTPS proxy settings without a further password. Ad-hoc builds cannot attest a client's code identity, only its UID. See `SECURITY.md`, `docs/VALIDATION.md` and `docs/RESEARCH.md` for exact scope.

Download the `arm64` ZIP for Apple Silicon or `x86_64` for Intel. Move the extracted app to Applications. Review the README's Gatekeeper instructions before opening this preview. Use the app's disconnect/recovery controls to restore owned proxy settings.
