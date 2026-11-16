#!/usr/bin/env bash
# Verify SwiftPM tests, macOS Debug/Release builds, and iOS Simulator tests/launch.
# Runs locally on macOS by default, or syncs to an explicitly provided SSH host.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/verify-apple-targets.sh [ssh-host]

Without arguments, verifies all Apple targets locally on macOS.
When an SSH host is explicitly provided, syncs this checkout to the remote Mac
and runs the same verification suite there.

Environment variables:
  FILEVAULT_SIMULATOR_NAME  Optional exact iOS simulator name (defaults to an available iPhone)
  FILEVAULT_REMOTE_DIR      Remote workspace relative to $HOME when using SSH (default: .cache/filevault-verify)
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -eq 1 ]]; then
  host="$1"
  remote_dir="${FILEVAULT_REMOTE_DIR:-.cache/filevault-verify}"
  simulator_name="${FILEVAULT_SIMULATOR_NAME:-}"

  if ! command -v ssh >/dev/null || ! command -v tar >/dev/null; then
    echo "error: ssh and tar are required for remote verification" >&2
    exit 1
  fi

  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "$host" \
    'xcode-select -p >/dev/null && xcodebuild -version >/dev/null && swift --version >/dev/null'

  echo "Syncing $repo_root to $host:~/$remote_dir"
  tar \
    --exclude=.git \
    --exclude=.build \
    --exclude=.swiftpm \
    --exclude=.xcode-derived* \
    --exclude=DerivedData \
    --exclude=build \
    --exclude=dist \
    --exclude='*.dmg' \
    -C "$repo_root" -cf - . \
    | ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$host" \
        "rm -rf \"\$HOME/$(printf '%q' "$remote_dir")\" && mkdir -p \"\$HOME/$(printf '%q' "$remote_dir")\" && tar -C \"\$HOME/$(printf '%q' "$remote_dir")\" -xf -"

  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes "$host" \
    "cd \"\$HOME/$(printf '%q' "$remote_dir")\" && FILEVAULT_SIMULATOR_NAME=$(printf '%q' "$simulator_name") bash scripts/verify-apple-targets.sh"

  echo "Apple target verification passed on $host."
  exit 0
fi

cd "$repo_root"

for tool in xcode-select xcodebuild swift xcrun plutil bash; do
  if ! command -v "$tool" >/dev/null; then
    echo "error: required tool '$tool' not found (must run on macOS with Xcode installed)" >&2
    exit 1
  fi
done

xcode-select -p >/dev/null

plutil -lint Info.plist Sources/FileVaultiOSApp/Info.plist
bash -n scripts/*.sh

schemes_output="$(xcodebuild -list -project FileVault.xcodeproj)"
for scheme in FileVaultMac FileVaultiOS; do
  if ! printf '%s\n' "$schemes_output" | grep -Fq "$scheme"; then
    echo "error: required Xcode scheme '$scheme' is missing" >&2
    exit 1
  fi
done

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
test -x .xcode-derived-mac-release/Build/Products/Release/FileVault.app/Contents/MacOS/FileVault

simulator_name="${FILEVAULT_SIMULATOR_NAME:-}"
udid="$(xcrun simctl list devices available | awk -v requested="$simulator_name" '
  /^-- iOS / { in_ios = 1; found_in_section = 0; next }
  /^-- / { in_ios = 0 }
  !in_ios { next }
  requested != "" {
    if (index($0, "    " requested " (") == 1 && match($0, /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/)) {
      last_udid = substr($0, RSTART, RLENGTH)
    }
    next
  }
  !found_in_section && /iPhone/ && match($0, /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/) {
    last_udid = substr($0, RSTART, RLENGTH)
    found_in_section = 1
  }
  END { if (last_udid != "") print last_udid }
')"

if [[ -z "$udid" ]]; then
  if [[ -n "$simulator_name" ]]; then
    echo "error: no available iOS simulator named '$simulator_name'" >&2
  else
    echo "error: no available iPhone simulator found" >&2
  fi
  exit 1
fi

echo "Using iOS simulator UDID: $udid"
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

echo "Local Apple target verification passed."
