# FileVault Native macOS App — Delivery Plan

## Decisions locked

- Remove all PWA runtime files, Node tests, PWA documentation, build output, manifest, service worker, and web icons. Retain repository history and the `FileVaultMac/` subtree only.
- Deliver a native macOS app as an Xcode project and a locally built `.app`; no signing or notarization in this phase.
- Supported formats remain `NNNN1` (decrypt only), `NNNN2` (read/write through 512 MiB), and `NNNN3` (read/write above 512 MiB), with no format changes.
- Folder selection recursively includes files, preserves POSIX relative paths, includes the selected folder's own name at the vault root, excludes `.DS_Store`, and does not represent empty directories.
- On output conflicts, default to **Keep Both**. Offer **Replace** and **Cancel** before writing output.
- All crypto and vault processing stays local. Passwords are not persisted.

## Delivery sequence

### 1. Native project conversion and cleanup

1. Create the Xcode app project around the existing `VaultCore` code, with separate `VaultCore` and test targets.
2. Add the `.nnnn` document type and launch/open routing to the Decrypt flow.
3. Remove PWA files only after the Xcode project and native tests build successfully on the Mac.
4. Replace PWA-specific documentation with native build, privacy, and format-compatibility documentation.

### 2. Secure filesystem foundation

1. Add scoped-access helpers for picker/opened URLs and balance every access lifetime.
2. Validate all untrusted decrypted paths: no absolute paths, traversal, empty components, or unsafe destination escapes.
3. Add preflight output planning: detect every conflict before creating a final output.
4. Implement the shared conflict resolver: Keep Both generates unique names, Replace explicitly removes only the selected target, Cancel performs no write.
5. Route every output through a temporary sibling location. On success, close and atomically move into the final path; on error or cancellation, clean up only the operation's temporary output.

### 3. Encrypt experience

1. Build drag-and-drop support for files and folders, plus **Choose Files…** and **Choose Folder…**.
2. Recursively enumerate selected folders, include the folder root in each stored path, skip `.DS_Store`, reject unreadable files, deduplicate selections, and show file count/total bytes.
3. Keep in-memory `NNNN2` at or below 512 MiB; use 64 MiB streaming `NNNN3` above it.
4. Report bytes processed, total bytes, percentage, elapsed time, and current phase.
5. Make encryption cancellable between reads and chunks. Cancellation must never leave a completed-looking vault.

### 4. Decrypt experience

1. Accept a single `.nnnn` vault by drag-and-drop, picker, Finder double-click, or Open With.
2. Inspect only the magic/header before password submission; route to v1/v2/v3 decoding.
3. Plan all destination paths and resolve conflicts before final output appears.
4. Stream v3 to temporary output while reporting byte progress; support cancellation and cleanup.
5. Treat authentication failures as the single user-facing result: **Wrong password or damaged vault**.

### 5. Verification

Use test-first cycles for each new behavior. The automated suite must cover:

- folder traversal, selected-root preservation, `.DS_Store` exclusion, nested paths, empty files, and duplicate selection handling;
- byte-progress totals and cancellation for v2/v3;
- output conflicts for Keep Both, Replace, and Cancel;
- no final vault/output after cancellation, authentication failure, truncation, or I/O failure;
- atomic output publication and cleanup;
- `.nnnn` magic routing and safe-path rejection;
- PWA-format compatibility fixtures for NNNN1/2/3, including Unicode and chunk boundaries.

Then build and test on the Mac with `swift test`, `xcodebuild`, and manual Finder/drop interaction. Confirm an `.nnnn` double-click opens the Decrypt flow.

## Deferred

- Developer ID signing, notarization, App Store release.
- Password storage, recovery keys, cloud sync, accounts, telemetry.
- Finder Quick Actions/extensions and vault previews.

## Start condition

Implementation begins only after SSH access to the MacBook is available, because the Xcode project and native `.app` must be built and verified there.
