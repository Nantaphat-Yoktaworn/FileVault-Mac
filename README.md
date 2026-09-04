# 🔐 FileVault — File Encryption PWA

A web app that encrypts files with a password, **100% on your device** — your files and password never leave it.
(No server, no database — just static files.)

## How to use
1. **Encrypt** 🔒 — pick one or **many files at once** (or a whole folder on desktop) → set a password → everything is bundled into a single `.nnnn` vault
2. **Decrypt** 🔓 — pick a `.nnnn` file → enter the same password → original files come back (original filenames included); multi-file vaults show a list with per-file Save buttons + Download all
3. Wrong password = decryption fails (AES-GCM verifies integrity automatically)

> 📱 On iPhone you can multi-select files in the picker (tap Select / long-press). iOS Safari can't pick a whole *folder* — that option appears on desktop browsers only.

## Large files (up to ~30 GB) — desktop Chrome/Edge

The app picks one of two engines automatically based on total size:

| Total size | Engine | Memory used | Works on |
|---|---|---|---|
| **≤ 512 MB** | in-memory (v2) | whole vault in RAM | every browser, incl. iPhone — auto-downloads |
| **> 512 MB** | streaming (v3) | ~128 MB flat, regardless of size | desktop Chrome/Edge only |

For large files the app reads and writes in **64 MB chunks straight to disk** via the File System Access API, so a 30 GB vault never has to fit in RAM:

- **Encrypt:** you'll get a *Save As* dialog to choose where the `.nnnn` vault is written; a progress bar tracks it.
- **Decrypt:** you'll get a *Choose Folder* dialog; the recovered files (and any sub-folders) are written into it.

> ⚠️ A large (v3) vault can only be opened on desktop Chrome/Edge — iPhone can't stream files that big. Keep files under 512 MB if you need them to open on iPhone too.

> ⚠️ **Forgot your password? The file cannot be recovered.** No backdoors, no shortcuts.

## Run locally (localhost)

It must be served over HTTP (opening the file directly via `file://` blocks the crypto APIs). Pick one:

```powershell
# If you have Python
python -m http.server 8080

# Or with Node
npx serve .
```

Then open http://localhost:8080

## Use on iPhone

Your computer's `localhost` is not reachable from an iPhone, and PWAs require HTTPS — the easiest path is a free deploy:

### Netlify (recommended, easiest)
1. Go to https://app.netlify.com/drop
2. Drag the entire `FileVault-PWA` folder onto the page
3. You get a URL like `https://xxxx.netlify.app` — open it on your iPhone

### Install as an app on iPhone
1. Open the URL in **Safari**
2. Tap the **Share** button (square with arrow) → **Add to Home Screen**
3. A FileVault icon appears on your home screen — it opens like a real app (works offline too)

> Even when deployed online, all encryption happens on your device — the server only hosts the HTML/JS files.

### Where files go on iPhone
Downloaded files are saved to the **Files** app → **Downloads**

## Tech

| Part | Technology |
|------|-----------|
| Encryption | AES-256-GCM (authenticated encryption) |
| Password → key | PBKDF2-SHA256, 600,000 rounds, random 16-byte salt |
| API | Web Crypto API (built into the browser, zero dependencies) |
| Offline | Service Worker + Cache API |

### `.nnnn` file formats

**v2 — in-memory multi-file vault** (≤ 512 MB)
```
[magic "NNNN2" 5B][salt 16B][iv 12B][ciphertext]
decrypted ciphertext =
  [file count 2B]
  per file: [name length 2B][filename][data length 4B][file data]
```

**v3 — streaming vault** (large files)
```
[magic "NNNN3" 5B][salt 16B][noncePrefix 8B][chunkSize u32][manifestLen u32]
[encrypted manifest chunk][encrypted data chunk 1][chunk 2]...
```
Each chunk is its own AES-GCM box: `iv = noncePrefix ‖ counter(u32)` (manifest = counter 0), and `aad = counter ‖ isLast` binds chunk order and end so the vault can't be reordered or truncated undetected. The manifest (chunk 0) is JSON `{ v, chunkSize, totalSize, files:[{name,size}] }`. The concatenated file stream is split into uniform `chunkSize` pieces regardless of file boundaries; manifest sizes reassemble it on decrypt.

Legacy v1 files (`NNNN1`, single file) still decrypt fine. In every format the filenames are encrypted inside the vault — someone looking at a `.nnnn` file can't tell what's in it or even how many files there are.

## Tests

```powershell
node test/roundtrip.test.mjs    # v1/v2 in-memory format
node test/streaming.test.mjs    # v3 streaming format (chunk + file boundaries, tamper, truncation)
```
