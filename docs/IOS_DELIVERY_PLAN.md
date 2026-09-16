# FileVault iPhone Delivery Plan

## Decisions

- Deliver a complete native iPhone app and retain macOS compatibility.
- Support iOS 17 and later.
- Decrypt into a user-selected Files folder.
- Verify with automated tests and an iOS Simulator. Physical-device signing, TestFlight, and App Store delivery are out of scope.
- Preserve every existing `NNNN1`, `NNNN2`, and `NNNN3` byte-format rule. Existing vaults must remain readable on both platforms.

## Acceptance checklist

- [ ] The portable `VaultCore` Swift package builds for macOS 14+ and iOS 17+ without importing AppKit or UIKit; both native targets compile the same core sources.
- [ ] The same static NNNN1, NNNN2, and NNNN3 fixture vaults decrypt to their expected content on macOS and the iOS Simulator.
- [ ] macOS can still create its current NNNN2/NNNN3 vaults and iOS can read them; iOS-created NNNN3 vaults can be read by macOS.
- [ ] The macOS app remains a separately buildable target and its existing picker, drag/drop, conflict, cancellation, and Finder-document behavior remain intact.
- [ ] An iOS app target provides encrypt, decrypt, progress, cancellation, `.nnnn` document importing, and `.nnnn` exporting.
- [ ] iOS starts and ends security-scoped Files access in the UI/application layer, never in `VaultCore`.
- [ ] Decryption restores into a user-selected folder and keeps the existing temporary-sibling/atomic-publication guarantee.
- [ ] All core tests, macOS app builds, and iOS Simulator tests/builds pass from `scripts/verify-apple-targets.sh`.

## Implementation sequence

### 1. Establish a shared target boundary

1. Keep `Sources/VaultCore` as the sole portable core source set. Both Xcode app targets and the Swift package compile that source set; do not duplicate it into platform-specific directories.
2. Update `Package.swift` to declare `.macOS(.v14)` and `.iOS(.v17)` for the library. Keep `VaultCoreTests` as the portable test suite.
3. Retain only platform-neutral imports and behavior in `Sources/VaultCore`. AppKit, UIKit, SwiftUI picker code, alert presentation, and document security scope belong in app targets.
4. Introduce a small shared operation/configuration API so the platform UI selects policy without duplicating encryption decisions. The configuration exposes the output format policy, streaming chunk size, progress, and cancellation only; it must not alter the established vault encoding rules.

### 2. Preserve format compatibility before refactoring

1. Add checked-in fixture vaults and matching plaintext manifests under `Tests/VaultCoreTests/Fixtures/` for NNNN1, NNNN2, and NNNN3.
2. Add fixture tests that assert format detection, complete restored filenames/content, wrong-password failure, tamper failure, and rejection of malformed input.
3. Add a test for an iOS-oriented small NNNN3 chunk size, then verify that the macOS build decodes it. Continue to use the current 64 MiB policy on macOS unless a separate product decision changes it.
4. Use TDD for each core behavior: make the fixture or behavioral test fail first, implement the smallest change, run the focused test, then run the full suite.

### 3. Improve core APIs for Files-provider URLs

1. Keep `VaultFileSource` URL-based, but let its size be supplied from a validated resource value when needed so the iOS UI can retain access to a Files-provider URL for the full operation.
2. Keep security-scoped resource acquisition/lifetime in an iOS `FileAccessScope` helper that is owned by the operation task. It must release every successful scope when the task finishes, fails, or is cancelled.
3. Review `VaultFileDiscovery` against iOS document-provider behavior. Do not assume access outside the selected tree; reject unreadable sources clearly. Preserve the existing symlink and unsafe-path protections.
4. Never use `Data(contentsOf:)` for an iOS large-file path. iOS encryption should choose NNNN3 streaming by default with a conservative configurable chunk size (initial value: 4 MiB). NNNN3 records its chunk size, so this remains interoperable with macOS.

### 4. Restructure macOS resources and target metadata

1. Rename the current app target/scheme to `FileVaultMac` while retaining the product display name `FileVault` and its bundle identifier unless the project requires a migration.
2. Move macOS-only `Info.plist` and assets under a macOS-specific resource directory. Retain the existing `.nnnn` UTI declaration.
3. Give `VaultCore` no app resources. Create separate iOS `Info.plist` and asset catalog, using the same UTI identifier and filename extension.
4. Build the existing macOS Debug and Release application with no signing required. Retain the DMG path only as a macOS distribution concern.

### 5. Build the iOS app target

1. Create a `FileVaultiOS` SwiftUI target for iOS 17, linked only to `VaultCore`, SwiftUI, Foundation, and UniformTypeIdentifiers.
2. Implement an operation screen matching the macOS functions rather than its AppKit layout:
   - Encrypt/decrypt segmented mode.
   - `fileImporter` for files/folders and one `.nnnn` vault.
   - `fileExporter` for encrypted output.
   - A folder picker backed by `UIDocumentPickerViewController` for a decryption destination.
   - Password and confirmation `SecureField`s, byte progress, elapsed time, cancel, and generic authentication-error copy.
3. Keep selected Files URLs scoped for the whole detached operation, not merely the picker callback. Run file work off the main actor; publish UI updates on the main actor.
4. On decrypt, write to an unpublished temporary sibling inside the selected folder, validate each restored relative path, then atomically publish it. If the provider cannot support required atomic rename semantics, fail before writing and explain that a local Files folder is required.
5. Register `com.nnnn.filevault.vault` as an imported/exported document type and confirm it appears in the iOS Files importer. A share extension is explicitly deferred.
6. Do not claim reliable arbitrary-duration background encryption: iOS may suspend the app. Use a foreground operation with cancellation and a background task assertion only to finish a transition safely.

### 6. Test and verify on the Mac

1. Use `nnnnmacbook`, verified as `NNNNs-MacBook-Air.local` with Xcode 26.6 and available iOS Simulator runtimes.
2. Run portable core tests through SwiftPM and the Xcode test target.
3. Build and test the macOS target without signing.
4. Boot an available iPhone simulator, build and test `FileVaultiOS` with signing disabled, install it, launch it, and verify the process/application identifier is present.
5. Perform a focused simulator smoke test for: importing a fixture vault, rejecting a wrong password, completing a small streaming round trip, and showing the selected destination workflow. Automated unit tests establish the encryption results; this smoke test establishes application integration.
6. Run `scripts/verify-apple-targets.sh` from the controller checkout as the final reproducible verification command.

## Manual work that remains outside this delivery

- Apple Developer team enrollment, device provisioning, physical-iPhone testing, TestFlight, App Store submission, signing, and notarization.
- User confirmation of visual polish and Files-provider behavior on a physical iPhone.
- iCloud Drive-specific background-transfer guarantees.
