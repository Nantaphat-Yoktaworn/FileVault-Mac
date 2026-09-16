# FileVault for macOS and iPhone

FileVault is a native macOS 14+ and iOS 17+ app for creating and opening password-protected `.nnnn` vaults. Encryption, decryption, and key derivation run entirely on-device: passwords are never saved or sent over the network.

## Install

A drag-to-install disk image is produced at:

```text
~/Downloads/FileVault-0.1.0.dmg
```

Open the DMG and drag `FileVault.app` onto the `Applications` shortcut. The app is currently unsigned, so macOS may require **Control-click → Open** on first launch.

For a development build, open this bundle in Finder (show hidden files with **Command-Shift-.**):

```text
.xcode-derived/Build/Products/Debug/FileVault.app
```

## Features

- Encrypt one or more files, or recursively encrypt a selected folder.
- Drag files and folders into the Encrypt panel, or use **Choose Files…** / **Choose Folder…**.
- Drop or choose one `.nnnn` vault to decrypt.
- Preserve the selected folder name and nested relative paths; ignore `.DS_Store`; empty folders are not stored.
- Report processed and total bytes plus elapsed time while an operation runs.
- Cancel ongoing operations. Unfinished vaults and partially restored folders are cleaned up instead of being published.
- Resolve an existing output name with **Keep Both** (default), **Replace**, or **Cancel** before output is written.
- Register the `.nnnn` document type for Finder and Open With.
- Use the FileVault shield icon in the app window, Dock, and Finder.

## iPhone

The **FileVaultiOS** scheme builds an iPhone app for iOS 17+. It imports files, folders, and `.nnnn` vaults through the Files app; encrypts to a temporary NNNN3 vault using 4 MiB chunks; then presents the system export picker. Decryption restores into a user-selected Files folder. The app accesses security-scoped Files URLs only for the active operation and supports NNNN1, NNNN2, and NNNN3 decryption.

Build and launch it in an available simulator from a Linux controller with:

```sh
./scripts/verify-apple-targets.sh nnnnmacbook
```

## Vault compatibility

- `NNNN1`: decrypt legacy single-file vaults.
- `NNNN2`: encrypt and decrypt vaults up to 512 MiB in memory.
- `NNNN3`: encrypt and decrypt larger vaults in 64 MiB authenticated chunks.

All supported formats use AES-256-GCM and PBKDF2-HMAC-SHA256 with 600,000 iterations. Vault byte layouts are compatibility-sensitive and are intentionally unchanged.

## Build and verify on macOS

Open `FileVault.xcodeproj` in Xcode, select the **FileVault** scheme, and Run. Command-line verification:

```sh
swift test
xcodebuild -project FileVault.xcodeproj -scheme FileVault -configuration Debug -derivedDataPath .xcode-derived CODE_SIGNING_ALLOWED=NO build
```

Create the installable DMG from a Release build:

```sh
xcodebuild -project FileVault.xcodeproj -scheme FileVault -configuration Release -derivedDataPath .xcode-derived-release CODE_SIGNING_ALLOWED=NO build
rm -rf /tmp/FileVault-Installer ~/Downloads/FileVault-0.1.0.dmg
mkdir -p /tmp/FileVault-Installer
cp -R .xcode-derived-release/Build/Products/Release/FileVault.app /tmp/FileVault-Installer/
ln -s /Applications /tmp/FileVault-Installer/Applications
hdiutil create -volname FileVault -srcfolder /tmp/FileVault-Installer -ov -format UDZO ~/Downloads/FileVault-0.1.0.dmg
```

## Privacy and security behavior

Passwords exist only for the active operation and are cleared after it completes. Encrypt and decrypt operations write to temporary sibling locations, then publish the result only after successful completion. Authentication failures are shown as a single generic message: **Wrong password or damaged vault.**

## Delivery status

The core suite covers format detection, v2 round trips and wrong-password handling, output planning, folder discovery, streaming round trips, tampering, cancellation, and cleanup. The Debug and Release macOS app builds have been verified locally on the Mac. Developer ID signing, notarization, and distribution outside the local DMG remain deferred.

See [the delivery record](docs/DELIVERY.md) for the full scope and verification history.
