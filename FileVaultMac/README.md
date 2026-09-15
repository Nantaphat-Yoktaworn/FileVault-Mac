# FileVault for macOS

Native macOS 14+ file and folder encryption app. It creates password-protected `.nnnn` vaults locally and never saves passwords or sends data over the network.

## Current format support

- `NNNN1`: decrypt legacy single-file vaults.
- `NNNN2`: encrypt/decrypt vaults up to 512 MiB in memory.
- `NNNN3`: encrypt/decrypt larger vaults using 64 MiB authenticated chunks.

All formats use AES-256-GCM and PBKDF2-HMAC-SHA256 with 600,000 iterations. The byte layout is compatibility-sensitive.

## Build on macOS

Open `FileVault.xcodeproj` in Xcode, choose the **FileVault** scheme, and Run. The project builds an unsigned local `FileVault.app` in this phase.

CLI verification:

```sh
swift test
xcodebuild -project FileVault.xcodeproj -scheme FileVault -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

## Product plan

See [NATIVE_APP_PLAN.md](NATIVE_APP_PLAN.md) for the agreed native-only delivery plan and acceptance criteria.

## Privacy

FileVault performs encryption, decryption, and key derivation on-device. Passwords are retained only for the active operation and cleared when it finishes.
