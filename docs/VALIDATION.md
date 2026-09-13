# Verification record

This file distinguishes executable evidence from pending acceptance. It is
updated with actual results before the preview tag is published.

| Area | Status |
| --- | --- |
| Original feature and license analysis | Complete; sources in RESEARCH.md |
| Rust formatting, lint and tests | Pending implementation checks |
| Swift model and recovery tests | Pending native macOS CI |
| arm64 and x86_64 app build | Pending native macOS CI |
| Real TLS through DoH and SNI fragmentation | Pending execution |
| App bundle signing integrity and process launch | Pending native macOS CI |
| User's MacBook UI, Safari/Chrome, sleep/wake and network switching | Not yet observed |
| Real user-session admin prompt and crash recovery | Not yet observed on a user's Mac |
| Developer ID and Apple notarization | Not performed; no signing credentials supplied |
| ISP/DPI effectiveness | Not established; depends on network and destination |

The CI smoke test uses a temporary loopback proxy and public `example.com` HTTPS
requests, checks origin certificates, and never enables the system proxy. It
must not be presented as proof of system-wide DNS protection or user-device QA.
