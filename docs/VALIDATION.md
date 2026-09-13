# Verification record

## Observed native verification

On 2026-09-13, commit `790411bef2393674da90bcabeb358d44d33e3ebb`
passed the complete [Apple Silicon and Intel macOS workflow](https://github.com/seungminkangg/veildns/actions/runs/34762078261).
The observed toolchains were Xcode 26.6 / Swift 6.3.3 and Rust 1.98.1;
the arm64 host reported macOS 26.6.2.

| Check | Observed result on both native architectures |
| --- | --- |
| Rust formatting and Clippy with warnings denied | PASS |
| Rust unit, loopback and real subprocess tests | 17 PASS |
| Swift configuration, restoration and command escaping tests | 17 PASS |
| Native app, privileged helper and bundle packaging | PASS |
| Ad-hoc signature integrity and property list validation | PASS |
| Real helper: engine exit, app crash, foreign edit preservation, stale identity rejection | 4 scenarios PASS using a disabled, isolated service |
| Cloudflare and Google DoH through the CONNECT proxy | Both PASS with origin certificate verification and TLS 1.3 |
| App launch and dynamic library loading | PASS; no launch log errors |
| Visual inspection | Actual arm64 launch screenshot inspected; see README |

Windows separately passed the same 17 Rust tests. The final smoke harness also
observed `fragmented: 1`, `errors: 0`, a complete public HTTPS response, graceful
stdin-EOF shutdown and a zero exit status for **each** DoH provider.

## Release gates

The preview additionally checks current-service selection (three Swift tests),
verifies isolated-service cleanup and current-set membership, waits for configd
restoration, and rejects delayed callbacks from a previous engine launch.
The [release workflow](../.github/workflows/ci.yml) repeats native tests, builds,
real helper scenarios, live HTTPS and launch checks on the exact release commit.
It creates a public prerelease only after both architecture jobs succeed. The
release tag, workflow SHA and artifact hashes identify the shipped code and files.

The actual helper test never adds its temporary service to the active network
set. It verifies the original set and existing service dictionaries are unchanged,
checks removal of its service and journal, and reports success after cleanup.
The HTTPS smoke test uses a temporary loopback port and `example.com`. It does
not change the runner's active system proxy.

## Not established by these checks

- A person's MacBook using Safari/Chrome, the administrator dialog, sleep/wake,
  captive portals, VPN coexistence, or real network-interface switching.
- Runtime compatibility on the minimum macOS 15 deployment target. The binary
  targets macOS 15, while observed native CI used macOS 26.
- Installing the optional DNS profiles and observing their effective routing on
  a person's Mac. Both profiles passed static plist and payload validation.
- Developer ID identity or Apple notarization. The preview is ad-hoc signed;
  no Apple signing credentials were supplied or embedded.
- Effectiveness against any particular ISP/DPI system, all-application coverage,
  UDP/QUIC forwarding, or an external security audit.

Proxy setting persistence means a power loss or forced system shutdown can leave
a recovery journal and saved proxy settings. Reopen VeilDNS and use recovery before
starting a new session. The crash watcher handles normal observed process exits;
it cannot run while the machine has no power.
