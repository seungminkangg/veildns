# Security

VeilDNS listens on IPv4 loopback. Local processes on the same Mac can use that
listener while it runs; there is no per-application proxy authentication. The
engine rejects non-public destinations by default. `allow_private` is intended
only for explicit CLI testing and is disabled by the app.

HTTPS remains between the browser and the origin server. The application does
not install a root certificate or decrypt HTTPS. DNS queries are shared with the
selected DoH provider. The provider and destination server retain their normal
visibility; this is not an anonymity system.

The GUI and engine run as the user. A separate, temporary privileged helper
changes only scoped system proxy settings and restores values still owned by
the session. Configuration and recovery journals are local. Preview artifacts
are ad-hoc signed, so users must assess the publisher before opening them.

Report suspected vulnerabilities privately using the repository's Security tab
when private reporting is available. Otherwise open an issue requesting a private
contact without including exploit details or personal data. Do not include real
browsing domains, access tokens, or network credentials in reports.

Only the latest published preview is maintained at present. This project has
not undergone an external security audit.
