# macOS distribution

The public preview ZIP contains a native `VeilDNS.app`, the matching-architecture
Rust engine, a native SystemConfiguration helper, an icon, and license notices.
The app targets macOS 15+. Separate arm64 and x86_64 archives avoid bundling the
wrong engine architecture. SHA-256 files accompany the artifacts.

## Reproduce

On the target architecture with Xcode 26.6+ and rustup installed:

```bash
cargo test --manifest-path engine/Cargo.toml --locked
swift test --package-path macos
bash scripts/build-macos.sh
python3 scripts/smoke-proxy.py build/VeilDNS.app/Contents/Resources/veildns-engine
bash scripts/smoke-app.sh
```

GitHub Actions runs the corresponding build and checks on Apple Silicon and
Intel macOS runners. Tag builds publish a prerelease only after both jobs pass.
The source tag, lockfile, runner logs and artifact hashes identify the inputs and
outputs. This is a repeatable build recipe, not a claim of bit-for-bit reproducibility.

## Developer ID signing and notarization

Default builds use ad-hoc signing (`codesign --sign -`) with the hardened runtime.
This proves local bundle integrity; it does **not** establish a trusted developer
identity or satisfy Gatekeeper's notarization policy.

An authorized maintainer can use their existing Developer ID certificate and a
notarytool keychain profile. Keep certificates and notarization credentials out
of the repository, build output and shell logs.

```bash
SIGNING_IDENTITY='Developer ID Application: Your Name (TEAMID)' \
NOTARY_PROFILE='your-existing-notary-profile' \
bash scripts/build-macos.sh
```

The script signs embedded executables before the app, submits with `--wait`,
staples and validates the ticket, assesses Gatekeeper, and recreates the ZIP with
the stapled app. Failed notarization stops the build. It does not pretend that a
certificate was available or disable Gatekeeper to make checks pass.

References: [Apple notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution),
[Apple opening an app from an unidentified developer](https://support.apple.com/en-us/102445).
