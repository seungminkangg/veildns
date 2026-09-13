#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'Build the macOS app on a Mac with Xcode 26.6 or newer.' >&2
  exit 1
fi
VERSION="$(cat VERSION | tr -d '\r\n')"
ARCH="$(uname -m)"
APP="$PWD/build/VeilDNS.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$PWD/dist"
cargo build --manifest-path engine/Cargo.toml --release --locked
swift build --package-path macos -c release
SWIFT_BIN="$(swift build --package-path macos -c release --show-bin-path)"
install -m 755 "$SWIFT_BIN/VeilDNS" "$APP/Contents/MacOS/VeilDNS"
install -m 755 "$SWIFT_BIN/VeilDNSProxyHelper" "$APP/Contents/Resources/VeilDNSProxyHelper"
install -m 755 engine/target/release/veildns-engine "$APP/Contents/Resources/veildns-engine"
cp LICENSE "$APP/Contents/Resources/LICENSE.txt"
cp README.md "$APP/Contents/Resources/README.md"
mkdir -p "$APP/Contents/Resources/Profiles"
cp profiles/*.mobileconfig "$APP/Contents/Resources/Profiles/"
cp docs/SYSTEM_DNS.md "$APP/Contents/Resources/Profiles/README.md"
python3 profiles/validate_profiles.py
python3 scripts/dependency-notices.py > "$APP/Contents/Resources/THIRD_PARTY_NOTICES.txt"
swift scripts/make-icon.swift "$PWD/build"
iconutil -c icns "$PWD/build/VeilDNS.iconset" -o "$APP/Contents/Resources/VeilDNS.icns"
python3 - "$APP" "$VERSION" <<'PY'
import plistlib, sys
from pathlib import Path
app, version = Path(sys.argv[1]), sys.argv[2]
info = {
    "CFBundleDevelopmentRegion": "ko",
    "CFBundleDisplayName": "VeilDNS",
    "CFBundleExecutable": "VeilDNS",
    "CFBundleIdentifier": "io.github.seungminkangg.veildns",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "VeilDNS",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": version.split("-")[0],
    "CFBundleVersion": "1",
    "CFBundleIconFile": "VeilDNS",
    "LSMinimumSystemVersion": "15.0",
    "NSHighResolutionCapable": True,
    "NSPrincipalClass": "NSApplication",
    "NSHumanReadableCopyright": "Copyright 2026 VeilDNS contributors. MIT License.",
}
(app / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
PY
IDENTITY="${SIGNING_IDENTITY:--}"
SIGN_ARGS=(--force --sign "$IDENTITY" --options runtime)
if [[ "$IDENTITY" != '-' ]]; then SIGN_ARGS+=(--timestamp); fi
codesign "${SIGN_ARGS[@]}" "$APP/Contents/Resources/veildns-engine"
codesign "${SIGN_ARGS[@]}" "$APP/Contents/Resources/VeilDNSProxyHelper"
codesign "${SIGN_ARGS[@]}" "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
plutil -lint "$APP/Contents/Info.plist"
ZIP="$PWD/dist/VeilDNS-$VERSION-macos-$ARCH.zip"
ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  if [[ "$IDENTITY" == '-' ]]; then echo 'Notarization requires SIGNING_IDENTITY.' >&2; exit 1; fi
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json > "$PWD/build/notary-result.json"
  python3 - "$PWD/build/notary-result.json" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
if result.get("status") != "Accepted":
    raise SystemExit("Notarization did not return Accepted; no release package approved.")
PY
  xcrun stapler staple "$APP"
  xcrun stapler validate "$APP"
  spctl --assess --type execute --verbose=2 "$APP"
  ditto -c -k --sequesterRsrc --keepParent "$APP" "$ZIP"
fi
(cd "$PWD/dist" && shasum -a 256 "$(basename "$ZIP")" > "$(basename "$ZIP").sha256")
echo "Built $ZIP"
