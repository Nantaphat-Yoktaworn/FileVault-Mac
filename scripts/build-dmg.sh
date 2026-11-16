#!/usr/bin/env bash
# Build an unsigned Release FileVault.app and package it into a drag-to-install DMG.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for tool in xcodebuild codesign hdiutil ditto mktemp shasum; do
  if ! command -v "$tool" >/dev/null; then
    echo "error: required tool '$tool' not found" >&2
    exit 1
  fi
done

derived_data_path="${FILEVAULT_DERIVED_DATA_PATH:-$repo_root/.xcode-derived-mac-release}"
build_dir="$repo_root/build"
dist_dir="$repo_root/dist"

version="${FILEVAULT_VERSION:-}"
if [[ -z "$version" ]]; then
  version="$(xcodebuild -project FileVault.xcodeproj -scheme FileVaultMac -configuration Release -showBuildSettings 2>/dev/null | awk -F ' = ' '/MARKETING_VERSION = / { print $2; exit }')"
  version="${version:-0.1.0}"
fi

xcodebuild \
  -project FileVault.xcodeproj \
  -scheme FileVaultMac \
  -configuration Release \
  -derivedDataPath "$derived_data_path" \
  CODE_SIGNING_ALLOWED=NO \
  build

app_bundle="$derived_data_path/Build/Products/Release/FileVault.app"
if [[ ! -x "$app_bundle/Contents/MacOS/FileVault" ]]; then
  echo "error: expected Release app bundle at $app_bundle" >&2
  exit 1
fi

mkdir -p "$build_dir" "$dist_dir"
staging_dir="$(mktemp -d "$build_dir/dmg-staging.XXXXXX")"
trap 'rm -rf "$staging_dir"' EXIT

ditto "$app_bundle" "$staging_dir/FileVault.app"
codesign --force --sign - "$staging_dir/FileVault.app"
codesign --verify --strict "$staging_dir/FileVault.app"
ln -s /Applications "$staging_dir/Applications"

dmg_path="$dist_dir/FileVault-$version.dmg"
rm -f "$dmg_path"

hdiutil create \
  -volname "FileVault" \
  -srcfolder "$staging_dir" \
  -ov \
  -format UDZO \
  "$dmg_path"

echo "Built DMG: $dmg_path"
shasum -a 256 "$dmg_path"
