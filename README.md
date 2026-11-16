# FileVault for macOS and iPhone

FileVault is a native macOS 14+ and iOS 17+ app for creating and opening password-protected `.nnnn` vaults. Key derivation, encryption, and decryption run entirely on-device—passwords are never persisted or sent over the network.

## Features

### macOS (`FileVaultMac`)
- Encrypt one or more files, or recursively encrypt a selected folder.
- Drag and drop files or folders directly into the Encrypt zone, or use **Choose Files…** / **Choose Folder…**.
- Drop, browse, or open a `.nnnn` vault from Finder (**Open With**) to decrypt.
- Preserve the selected root folder name and nested relative paths while skipping `.DS_Store` and symlinks (empty directories are not stored).
- Live byte progress, elapsed time, and **Cancel** support (incomplete outputs are deleted rather than published).
- Output conflict prompt with **Keep Both** (default), **Replace**, and **Cancel** before final publication.
- Exported document type (`com.nnnn.filevault.vault` / `.nnnn`) and FileVault shield icon in the window, Dock, and Finder.

### iPhone (`FileVaultiOS`)
- Native SwiftUI app targeting iOS 17+.
- Import files, folders, and `.nnnn` vaults from the system Files app (`fileImporter`) and export encrypted `.nnnn` vaults using a `UIDocumentPickerViewController` export picker.
- Encrypt using 4 MiB chunked `NNNN3` streaming to keep memory usage bounded on mobile devices.
- Decrypt `NNNN1`, `NNNN2`, and `NNNN3` vaults into a user-selected Files folder with live byte progress and cancellation.
- Acquire security-scoped Files access in the app layer only for the duration of each active operation.

## Architecture

- [`Sources/VaultCore`](Sources/VaultCore): Platform-neutral Swift library (`VaultCodec`, `VaultStreaming`, `VaultFileDiscovery`, `VaultOutput`, `VaultFormat`) built on `Foundation`, `CryptoKit`, and `CommonCrypto` with no AppKit or UIKit dependencies. Shared by SwiftPM, `FileVaultMac`, and `FileVaultiOS`.
- [`Sources/FileVaultMacApp`](Sources/FileVaultMacApp): macOS SwiftUI + AppKit interface (`FileVaultMac` scheme).
- [`Sources/FileVaultiOSApp`](Sources/FileVaultiOSApp): iOS SwiftUI + `UIDocumentPickerViewController` interface (`FileVaultiOS` scheme).
- [`Tests/VaultCoreTests`](Tests/VaultCoreTests): Swift Testing suite covering format detection, `NNNN2` round trips, wrong-password rejection, output conflict planning, folder discovery, `NNNN3` streaming across chunk boundaries, tampering detection, cancellation, and cleanup.
- [`Tests/FileVaultiOSTests`](Tests/FileVaultiOSTests): XCTest suite verifying `NNNN1`, `NNNN2`, and `NNNN3` fixture decryption on the iOS Simulator.

## Requirements

- macOS 14.0+ (for the macOS app and local Xcode builds)
- iOS 17.0+ (for the iPhone app target)
- Xcode with Swift 6.0+ toolchain and an iOS Simulator runtime

## Vault Compatibility and Cryptography

- `NNNN1`: Legacy single-file vault decryption.
- `NNNN2`: In-memory authenticated multi-file vaults (used on macOS for payloads up to 512 MiB).
- `NNNN3`: Chunked authenticated streaming vaults with an encrypted JSON manifest (64 MiB chunks above 512 MiB on macOS; 4 MiB chunks on iOS).

All supported formats use **AES-256-GCM** with **PBKDF2-HMAC-SHA256** (600,000 iterations). Vault byte layouts, the `.nnnn` extension, and the `com.nnnn.filevault.vault` UTI are kept stable for cross-platform compatibility.

## Privacy and Security Design

- **Zero credential persistence**: Passwords live in memory only for the active operation and are cleared once it finishes or fails.
- **Atomic temporary-sibling publication**: Encrypted vaults and decrypted folders are staged in hidden temporary sibling locations and moved/replaced into the destination only after full verification. Cancelled or failed operations remove temporary artifacts.
- **Path validation**: Restored entries reject absolute paths, empty segments, `.`, and `..` traversal components.
- **Generic authentication feedback**: Decryption and authentication failures surface a single generic message (`Wrong password or damaged vault.`).

## Build and Verify Locally

### Run SwiftPM tests

```sh
swift test
```

### Build macOS targets (unsigned)

Open `FileVault.xcodeproj` in Xcode with the **FileVaultMac** scheme, or build from the command line:

```sh
xcodebuild -project FileVault.xcodeproj -scheme FileVaultMac -configuration Debug -derivedDataPath .xcode-derived-mac CODE_SIGNING_ALLOWED=NO build
xcodebuild -project FileVault.xcodeproj -scheme FileVaultMac -configuration Release -derivedDataPath .xcode-derived-mac-release CODE_SIGNING_ALLOWED=NO build
```

The Debug app bundle is produced at:

```text
.xcode-derived-mac/Build/Products/Debug/FileVault.app
```

### Run iOS Simulator tests

```sh
udid="$(xcrun simctl list devices available | awk '
  /^-- iOS / { in_ios = 1; found = 0; next }
  /^-- / { in_ios = 0 }
  in_ios && !found && /iPhone/ && match($0, /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/) {
    last = substr($0, RSTART, RLENGTH); found = 1
  }
  END { if (last != "") print last }
')"
xcrun simctl boot "$udid" 2>/dev/null || true
xcrun simctl bootstatus "$udid" -b
xcodebuild -project FileVault.xcodeproj -scheme FileVaultiOSTests -destination "platform=iOS Simulator,id=$udid" -configuration Debug -derivedDataPath .xcode-derived-ios CODE_SIGNING_ALLOWED=NO test
```

### Run full verification script

[`scripts/verify-apple-targets.sh`](scripts/verify-apple-targets.sh) runs `plutil -lint`, `bash -n`, `swift test`, macOS Debug/Release builds, `FileVaultiOSTests`, and iOS Simulator app install/launch locally on macOS (or against an explicitly passed SSH host):

```sh
./scripts/verify-apple-targets.sh
```

Continuous integration runs the same core, macOS, and iOS Simulator verification on `macos-latest` via [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Package and Install (macOS DMG)

Create a compressed drag-to-install DMG from a locally built Release app (ad-hoc signed, without Developer ID signing or notarization) using [`scripts/build-dmg.sh`](scripts/build-dmg.sh):

```sh
./scripts/build-dmg.sh
```

This outputs:

```text
dist/FileVault-0.1.0.dmg
```

Open the DMG and drag `FileVault.app` onto the `Applications` shortcut. Because local builds do not include Developer ID signing or notarization, macOS Gatekeeper may require **Control-click → Open** on first launch.

## Documentation

- [Delivery Record](docs/DELIVERY.md)
- [iPhone Delivery Plan](docs/IOS_DELIVERY_PLAN.md)

## License

Released under the [MIT License](LICENSE).
