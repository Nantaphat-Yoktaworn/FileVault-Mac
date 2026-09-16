#!/usr/bin/env bash
# Sync the authoritative checkout to a Mac and verify every Apple target.
set -euo pipefail

host="${1:-nnnnmacbook}"
remote_dir="${FILEVAULT_REMOTE_DIR:-Projects/FileVault-Mac}"
simulator_name="${FILEVAULT_SIMULATOR_NAME:-iPhone 17 Pro}"

if ! command -v ssh >/dev/null || ! command -v tar >/dev/null; then
  echo "error: ssh and tar are required on the controller" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "$host" \
  'xcode-select -p >/dev/null && xcodebuild -version >/dev/null && swift --version >/dev/null'

echo "Syncing $repo_root to $host:~/$remote_dir"
tar \
  --exclude=.git \
  --exclude=.build \
  --exclude=.xcode-derived \
  --exclude=.xcode-derived-release \
  --exclude=DerivedData \
  -C "$repo_root" -cf - . \
  | ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$host" \
      "rm -rf \"\$HOME/$(printf '%q' "$remote_dir")\" && mkdir -p \"\$HOME/$(printf '%q' "$remote_dir")\" && tar -C \"\$HOME/$(printf '%q' "$remote_dir")\" -xf -"

ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$host" \
  "REMOTE_DIR=\"\$HOME/$(printf '%q' "$remote_dir")\" SIMULATOR_NAME=$(printf '%q' "$simulator_name") bash -s" <<'REMOTE'
set -euo pipefail
cd "$REMOTE_DIR"

require_scheme() {
  xcodebuild -list -project FileVault.xcodeproj | grep -Fq "$1" || {
    echo "error: required Xcode scheme '$1' is missing" >&2
    exit 1
  }
}

require_scheme FileVaultMac
require_scheme FileVaultiOS

swift test

xcodebuild \
  -project FileVault.xcodeproj \
  -scheme FileVaultMac \
  -configuration Debug \
  -derivedDataPath .xcode-derived-mac \
  CODE_SIGNING_ALLOWED=NO \
  build

xcodebuild \
  -project FileVault.xcodeproj \
  -scheme FileVaultMac \
  -configuration Release \
  -derivedDataPath .xcode-derived-mac-release \
  CODE_SIGNING_ALLOWED=NO \
  build

test -x .xcode-derived-mac/Build/Products/Debug/FileVault.app/Contents/MacOS/FileVault

udid="$(xcrun simctl list devices available | awk -v name="$SIMULATOR_NAME" '\
  index($0, name " (") { split($0, parts, "("); value = parts[2]; gsub(/[ )]/, "", value); print value; exit }')"
if [ -z "$udid" ]; then
  echo "error: no available simulator named '$SIMULATOR_NAME'" >&2
  exit 1
fi

xcrun simctl boot "$udid" 2>/dev/null || true
xcrun simctl bootstatus "$udid" -b

xcodebuild \
  -project FileVault.xcodeproj \
  -scheme FileVaultiOSTests \
  -destination "platform=iOS Simulator,id=$udid" \
  -configuration Debug \
  -derivedDataPath .xcode-derived-ios \
  CODE_SIGNING_ALLOWED=NO \
  test

app_path=".xcode-derived-ios/Build/Products/Debug-iphonesimulator/FileVault.app"
test -d "$app_path"
xcrun simctl boot "$udid" 2>/dev/null || true
xcrun simctl bootstatus "$udid" -b
xcrun simctl install "$udid" "$app_path"
xcrun simctl launch "$udid" com.nnnn.FileVault.iOS
REMOTE

echo "Apple target verification passed on $host."
