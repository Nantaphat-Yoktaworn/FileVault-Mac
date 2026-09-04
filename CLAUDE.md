# FileVault-PWA

Static, offline PWA (no server, no build) that encrypts files into password-protected `.nnnn` vaults entirely on-device via the Web Crypto API. English UI. Started 2026-06-14.

## Stack / run
Plain `index.html` + `app.js` + `sw.js` + `manifest.json`. Serve over HTTP (not `file://`, which blocks crypto APIs): `python -m http.server 8080` → http://localhost:8080. Launch config in `.claude/launch.json`. Node tests in `test/`.

## Crypto
AES-256-GCM + PBKDF2-SHA256, 600k rounds, random 16-byte salt. Filenames are encrypted inside the vault too — a `.nnnn` file reveals nothing about contents or file count. No password recovery, by design.

## Two formats, picked automatically by total size (intentional, for cross-device compat)
- **≤512 MB → v2 in-memory (`NNNN2`)**: whole vault in RAM, auto-downloads, works everywhere incl. iPhone.
- **>512 MB → v3 streaming (`NNNN3`)**: 64 MB chunked AES-GCM read/written straight to disk via File System Access API; handles ~30 GB at ~128 MB flat RAM. **Desktop Chrome/Edge only** — iPhone can't open large v3 vaults.
- **v1 (`NNNN1`)** legacy single-file still decrypts.

v3 per-chunk box: `iv = noncePrefix ‖ counter(u32)` (manifest = counter 0), `aad = counter ‖ isLast` — binds chunk order + end so a vault can't be reordered or truncated undetected. Manifest (chunk 0) is JSON `{ v, chunkSize, totalSize, files:[{name,size}] }`. Full byte layout in README.md.

## Routing (app.js `run()`)
Encrypt: total > `STREAM_THRESHOLD` (512 MB) → streaming, else in-memory. Decrypt: route by magic bytes. File System Access pickers (`showSaveFilePicker`/`showDirectoryPicker`) must be the first await after the click to preserve the user gesture.

## Tests
```
node test/roundtrip.test.mjs    # v1/v2 in-memory
node test/streaming.test.mjs    # v3 streaming (chunk+file boundaries, tamper, truncation)
```
Tests mirror app.js byte layout; keep them in sync if the format changes.

## Notes
- User is a beginner (Python, no C#); explain trade-offs plainly. Replies in English.
- Don't touch the sibling `LifeTracker-PWA` project or its `.claude/launch.json` entry.
