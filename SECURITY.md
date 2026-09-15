# Security

VeilDNS listens on IPv4 loopback. Local processes on the same Mac can use that
listener while it runs; there is no per-application proxy authentication. The
engine rejects non-public destinations by default. `allow_private` is intended
only for explicit CLI testing and is disabled by the app.

HTTPS remains between the browser and the origin server. The application does
not install a root certificate or decrypt HTTPS. DNS queries are shared with the
selected DoH provider. The provider and destination server retain their normal
visibility; this is not an anonymity system.

The GUI and engine run as the user. A privileged helper changes only scoped
system proxy settings and restores values still owned by the session.
Configuration and recovery journals are local. Preview artifacts are ad-hoc
signed, so users must assess the publisher before opening them.

To avoid one authorization prompt per connection, the first authorized run
installs that helper as a launchd daemon that listens on a UNIX socket at
`/var/run/veildns/helper.sock`. The socket is chowned to the installing account
and set to mode 0600, and the daemon independently rejects every peer whose
effective UID is not that account. It accepts only apply, restore, status and
uninstall, and it reads one fixed recovery record derived from the verified peer
identity rather than from any client-supplied path.

The deliberate trade is that after installation, code running as the installing
account can change that account's scoped HTTP/HTTPS proxy settings without a
further password. Because preview builds are ad-hoc signed, the daemon cannot
attest the code identity of its client, only its UID. Users who prefer a prompt
per connection should use **권한 유지 해제** in the app, which removes the
launchd job and the installed tool.

Report suspected vulnerabilities privately using the repository's Security tab
when private reporting is available. Otherwise open an issue requesting a private
contact without including exploit details or personal data. Do not include real
browsing domains, access tokens, or network credentials in reports.

Only the latest published preview is maintained at present. This project has
not undergone an external security audit.
