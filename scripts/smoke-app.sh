#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
APP="$PWD/build/VeilDNS.app"
codesign --verify --deep --strict --verbose=2 "$APP"
"$APP/Contents/Resources/veildns-engine" --version
otool -L "$APP/Contents/MacOS/VeilDNS"
otool -L "$APP/Contents/Resources/VeilDNSProxyHelper"
# Launch without granting network changes. A successful process launch is only
# a bundle/dyld check, not an assertion about UI quality or real device acceptance.
"$APP/Contents/MacOS/VeilDNS" > "$PWD/build/app-launch.log" 2>&1 &
APP_PID=$!
trap 'kill "$APP_PID" 2>/dev/null || true' EXIT
sleep 5
if ! kill -0 "$APP_PID" 2>/dev/null; then
  cat "$PWD/build/app-launch.log"
  echo 'App exited during launch smoke test.' >&2
  exit 1
fi
if command -v screencapture >/dev/null 2>&1; then
  screencapture -x "$PWD/build/launch.png" || true
fi
echo 'App stayed alive for five seconds; no system network settings were changed.'
