# FileVault Native Apple App — Delivery Record

## Locked product decisions

- FileVault is native on macOS 14+ and iOS 17+; the prior PWA runtime, tests, documentation, and web assets were removed.
- Delivery is an Xcode macOS app and locally built `.app` / drag-to-install DMG. Developer ID signing and notarization are deferred.
- Vault formats remain unchanged: `NNNN1` decrypt-only, `NNNN2` for in-memory vaults through 512 MiB, and chunked `NNNN3` above 512 MiB.
- Folder selection recurses files, preserves the selected folder name at the vault root, skips `.DS_Store`, and does not represent empty directories.
- Output conflicts default to **Keep Both**, with explicit **Replace** and **Cancel** choices before a final output is written.
- Encryption, decryption, and key derivation stay local; passwords are never persisted.

## Delivered

### Native app and Finder integration

- Xcode project targeting macOS 14+.
- Xcode project has separate `FileVaultMac` and `FileVaultiOS` schemes that compile the same portable `Sources/VaultCore` source set.
- iPhone UI imports through Files, encrypts with 4 MiB NNNN3 streaming chunks, exports through the system picker, and decrypts NNNN1/2/3 vaults into a user-selected Files folder.
- `.nnnn` exported document type for Finder and Open With routing to the Decrypt flow.
- FileVault shield branding in the window, Dock, and Finder through an `AppIcon` asset catalog.
- Debug `.app` and a Release DMG with an Applications shortcut for drag-to-install distribution.

### Encrypt workflow

- Choose files, choose one folder, or drag files and folders into the app.
- Recursive source discovery with selected-root preservation, metadata exclusion, and duplicate rejection.
- NNNN2 output through 512 MiB and 64 MiB-chunked NNNN3 streaming above that threshold.
- Byte progress, elapsed time, and a Cancel control.
- Temporary sibling output with atomic publication only on success; cancellation removes unpublished output.

### Decrypt workflow

- Accept one `.nnnn` vault by picker or drag-and-drop; Finder routes declared vault documents into the Decrypt flow.
- Detect NNNN1, NNNN2, and NNNN3 formats before decryption.
- Use temporary output directories and publish only after integrity validation succeeds.
- Show generic wrong-password-or-damaged-vault feedback for authentication failures.
- Support byte progress and cancellation for streaming vaults.

### Output safety

- Validate relative vault paths before restoring content.
- Resolve destination conflicts with Keep Both, Replace, or Cancel.
- Keep Both generates a unique name; Replace publishes the completed result; Cancel performs no write.

## Verification completed

- Automated Swift suite covers format detection, v2 round trips, wrong passwords, output planning, folder discovery, NNNN3 round trips, tampering, cancellation, and incomplete-output cleanup.
- `swift test` completed successfully with 15 tests on the Mac.
- macOS Debug and Release Xcode builds completed successfully on the Mac.
- iOS Simulator Debug build completed, installed, and launched successfully on the Mac (`com.nnnn.FileVault.iOS`).
- The Release DMG was checksum-verified and mounted to confirm it contains `FileVault.app` and the `Applications` shortcut.
- Manual drag-and-drop testing confirmed file and folder drops work in the Encrypt flow.

## Deferred

- Developer ID signing, notarization, and App Store release.
- Password storage, recovery keys, cloud sync, accounts, and telemetry.
- Finder Quick Actions, extensions, and vault previews.
