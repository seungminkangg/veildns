VeilDNS is an independent open-source macOS implementation inspired by SecretDNS's public feature descriptions.

- Native SwiftUI window and menu bar control, Korean interface, domain rules and resolver selection.
- Rust loopback HTTP/CONNECT proxy, DoH, selective TLS ClientHello SNI record fragmentation, no HTTPS interception.
- Scoped proxy changes with a recovery journal and temporary crash-recovery helper.
- Separate Apple Silicon and Intel macOS packages, dependency license notices and SHA-256 checksums.

This is a **preview** for macOS 15+. Packages are **ad-hoc signed, not Apple-notarized**. Tests cover the protocol engine, app models, package launch and real HTTPS over the proxy on CI; they do not prove compatibility with every browser, VPN, network or ISP. System-proxy-ignoring apps and UDP/QUIC are outside proxy coverage. See `docs/VALIDATION.md` and `docs/RESEARCH.md` for exact scope.

Download the `arm64` ZIP for Apple Silicon or `x86_64` for Intel. Move the extracted app to Applications. Review the README's Gatekeeper instructions before opening this preview. Use the app's disconnect/recovery controls to restore owned proxy settings.
