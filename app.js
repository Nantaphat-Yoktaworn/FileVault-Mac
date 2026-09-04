'use strict';

/* ============================================================
   FileVault — client-side file encryption

   Two on-disk formats, both with encrypted filenames:

   • v1/v2 (in-memory) — whole vault held in RAM, one AES-GCM
     operation. Used for files up to STREAM_THRESHOLD. Works on
     every browser (incl. iPhone), auto-downloads the result.
       v2: [magic "NNNN2"][salt 16][iv 12][ciphertext]
           plaintext = [count u16] then per file
                       [nameLen u16][name][dataLen u32][data]
       v1: [magic "NNNN1"][salt 16][iv 12][ciphertext]
           plaintext = [nameLen u16][name][data]

   • v3 (streaming) — for big files (up to ~30 GB+). Reads/writes
     in 64 MB chunks straight to disk via the File System Access
     API, so memory stays flat. Desktop Chrome/Edge only.
       [magic "NNNN3"][salt 16][noncePrefix 8][chunkSize u32]
       [manifestLen u32][manifest chunk][data chunk 1][2]...
     Each chunk is its own AES-GCM box:
       iv  = noncePrefix(8) || counter(u32 BE)   (manifest = 0)
       aad = counter(u32 BE) || isLast(1)         (binds order/end)
     Manifest (chunk 0) is JSON: { v, chunkSize, totalSize, files:[{name,size}] }
     The concatenated file stream is split into uniform chunks
     regardless of file boundaries; the manifest sizes put it
     back together on decrypt.
   ============================================================ */

const MAGIC_V1 = new TextEncoder().encode('NNNN1');
const MAGIC_V2 = new TextEncoder().encode('NNNN2');
const MAGIC_V3 = new TextEncoder().encode('NNNN3');
const PBKDF2_ITERS = 600000;
const EXT = '.nnnn';
const CHUNK_SIZE = 64 * 1024 * 1024;            // 64 MB plaintext per streamed chunk
const STREAM_THRESHOLD = 512 * 1024 * 1024;     // above this, stream to disk (needs File System Access)

// ---------- DOM ----------
const $ = (id) => document.getElementById(id);
const tabEnc = $('tabEnc'), tabDec = $('tabDec');
const drop = $('drop'), fileInput = $('fileInput'), folderInput = $('folderInput');
const pickFolderBtn = $('pickFolderBtn');
const sumTitle = $('sumTitle'), sumSub = $('sumSub'), sumIcon = $('sumIcon');
const fileList = $('fileList'), pickActions = $('pickActions'), clearAllBtn = $('clearAllBtn');
const results = $('results'), resultActions = $('resultActions'), dlAllBtn = $('dlAllBtn');
const pwInput = $('password'), pw2Input = $('password2');
const pwLabel = $('pwLabel'), confirmField = $('confirmField');
const togglePw = $('togglePw');
const strengthWrap = $('strengthWrap'), strengthBar = $('strengthBar');
const goBtn = $('goBtn'), statusBox = $('status');
const progressWrap = $('progress'), progressBar = $('progressBar'), progressText = $('progressText');
const dropTitle = $('dropTitle'), dropSub = $('dropSub'), dropIcon = $('dropIcon');

let mode = 'enc';       // 'enc' | 'dec'
let pickedFiles = [];   // File[]
let decrypted = [];     // {name, blob}[] — last in-memory decrypt result

// ---------- UI helpers ----------
function setMode(m) {
  mode = m;
  const enc = m === 'enc';
  tabEnc.className = 'mode-btn' + (enc ? ' active-enc' : '');
  tabDec.className = 'mode-btn' + (enc ? '' : ' active-dec');
  goBtn.className = 'go ' + m;
  goBtn.textContent = enc ? '🔒 Encrypt Files' : '🔓 Decrypt File';
  pwLabel.textContent = enc ? 'Set a password' : 'Enter this file\'s password';
  confirmField.style.display = enc ? '' : 'none';
  strengthWrap.style.display = enc ? '' : 'none';
  dropIcon.textContent = enc ? '📁' : '🗝️';
  dropTitle.textContent = enc ? 'Tap to choose files' : 'Tap to choose a ' + EXT + ' file';
  dropSub.textContent = enc ? 'Pick one or many — photos, videos, documents' : 'Pick a file you encrypted earlier';
  fileInput.accept = enc ? '' : EXT;
  fileInput.multiple = enc;
  pickFolderBtn.style.display = (enc && folderSupported()) ? 'block' : 'none';
  clearPicked();
  clearResults();
  hideStatus();
  hideProgress();
}

function folderSupported() {
  return 'webkitdirectory' in document.createElement('input') && !isIOS();
}

function fsaAvailable() {
  return typeof window.showSaveFilePicker === 'function' &&
         typeof window.showDirectoryPicker === 'function';
}

function fmtSize(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

function iconFor(name) {
  const n = name.toLowerCase();
  if (n.endsWith(EXT)) return '🔐';
  if (/\.(jpe?g|png|gif|webp|heic|bmp|svg)$/.test(n)) return '🖼️';
  if (/\.(mp4|mov|mkv|avi|webm)$/.test(n)) return '🎬';
  if (/\.(mp3|m4a|wav|flac|aac)$/.test(n)) return '🎵';
  if (/\.(pdf)$/.test(n)) return '📕';
  if (/\.(zip|rar|7z|tar|gz)$/.test(n)) return '🗜️';
  if (/\.(docx?|txt|md|rtf)$/.test(n)) return '📝';
  if (/\.(xlsx?|csv)$/.test(n)) return '📊';
  return '📄';
}

function entryName(f) {
  // Keep folder structure in the name when a whole folder was picked
  return (f.webkitRelativePath && f.webkitRelativePath.length) ? f.webkitRelativePath : f.name;
}

function addFiles(list) {
  const arr = Array.from(list).filter(f => !/(^|\/)\.(DS_Store|Thumbs\.db)$/i.test(entryName(f)));
  if (!arr.length) return;

  // Picking a single .nnnn while nothing is selected → jump to decrypt mode
  if (mode === 'enc' && pickedFiles.length === 0 && arr.length === 1 &&
      arr[0].name.toLowerCase().endsWith(EXT)) {
    const f = arr[0];
    setMode('dec');
    pickedFiles = [f];
    renderPicked();
    return;
  }

  if (mode === 'dec') {
    pickedFiles = [arr[0]];
  } else {
    for (const f of arr) {
      const name = entryName(f);
      if (!pickedFiles.some(p => entryName(p) === name && p.size === f.size)) pickedFiles.push(f);
    }
  }
  renderPicked();
  hideStatus();
  hideProgress();
  clearResults();
}

function renderPicked() {
  const n = pickedFiles.length;
  if (!n) {
    drop.classList.remove('has-file');
    fileList.classList.remove('show');
    pickActions.classList.remove('show');
    updateGo();
    return;
  }
  const total = pickedFiles.reduce((s, f) => s + f.size, 0);
  drop.classList.add('has-file');
  sumIcon.textContent = n === 1 ? iconFor(entryName(pickedFiles[0])) : '📦';
  sumTitle.textContent = n === 1 ? entryName(pickedFiles[0]) : n + ' files — ' + fmtSize(total);
  let sub = mode === 'enc' ? 'Tap to add more files' : fmtSize(total);
  if (mode === 'enc' && total > STREAM_THRESHOLD) {
    sub += fsaAvailable() ? ' • streams to disk 💪' : ' • ⚠️ too big for this device';
  }
  sumSub.textContent = sub;

  fileList.innerHTML = '';
  pickedFiles.forEach((f, i) => {
    const row = document.createElement('div');
    row.className = 'frow';
    row.innerHTML =
      '<span class="fi">' + iconFor(entryName(f)) + '</span>' +
      '<div class="fmeta"><div class="fname">' + escapeHtml(entryName(f)) + '</div>' +
      '<div class="fsize">' + fmtSize(f.size) + '</div></div>' +
      '<button class="fx" title="Remove">✕</button>';
    row.querySelector('.fx').addEventListener('click', () => {
      pickedFiles.splice(i, 1);
      renderPicked();
    });
    fileList.appendChild(row);
  });
  // in decrypt mode the drop-zone summary already shows the single file
  fileList.classList.toggle('show', mode === 'enc');
  pickActions.classList.toggle('show', mode === 'enc' && n > 1);
  updateGo();
}

function clearPicked() {
  pickedFiles = [];
  fileInput.value = '';
  folderInput.value = '';
  renderPicked();
}

function clearResults() {
  decrypted = [];
  results.innerHTML = '';
  results.classList.remove('show');
  resultActions.classList.remove('show');
}

function showResults(entries) {
  decrypted = entries;
  results.innerHTML = '';
  entries.forEach((en) => {
    const row = document.createElement('div');
    row.className = 'frow';
    row.innerHTML =
      '<span class="fi">' + iconFor(en.name) + '</span>' +
      '<div class="fmeta"><div class="fname">' + escapeHtml(en.name) + '</div>' +
      '<div class="fsize">' + fmtSize(en.blob.size) + '</div></div>' +
      '<button class="dl">⬇️ Save</button>';
    row.querySelector('.dl').addEventListener('click', () => downloadBlob(en.blob, safeName(en.name)));
    results.appendChild(row);
  });
  results.classList.add('show');
  resultActions.classList.toggle('show', entries.length > 1);
}

function updateGo() {
  const pwOk = pwInput.value.length > 0 && (mode === 'dec' || pw2Input.value.length > 0);
  goBtn.disabled = !(pickedFiles.length && pwOk);
  if (mode === 'enc') {
    goBtn.textContent = pickedFiles.length > 1
      ? '🔒 Encrypt ' + pickedFiles.length + ' Files'
      : '🔒 Encrypt File';
  }
}

function showStatus(kind, html) {
  statusBox.className = 'status show ' + kind;
  statusBox.innerHTML = html;
}
function hideStatus() { statusBox.className = 'status'; }

function showProgress(done, total) {
  progressWrap.classList.add('show');
  setProgress(done, total);
}
function setProgress(done, total) {
  const pct = total > 0 ? Math.min(100, (done / total) * 100) : 100;
  progressBar.style.width = pct.toFixed(1) + '%';
  progressText.textContent = fmtSize(done) + ' / ' + fmtSize(total) + '  (' + pct.toFixed(0) + '%)';
}
function hideProgress() { progressWrap.classList.remove('show'); }

function pwStrength(p) {
  let s = 0;
  if (p.length >= 8) s++;
  if (p.length >= 12) s++;
  if (/[a-z]/.test(p) && /[A-Z]/.test(p)) s++;
  if (/\d/.test(p)) s++;
  if (/[^a-zA-Z0-9]/.test(p)) s++;
  return Math.min(s, 5);
}

// ---------- Crypto core ----------
async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function matchMagic(buf, magic) {
  for (let i = 0; i < magic.length; i++) if (buf[i] !== magic[i]) return false;
  return true;
}

function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
function writeU32(arr, off, v) {
  arr[off] = (v >>> 24) & 0xff; arr[off + 1] = (v >>> 16) & 0xff;
  arr[off + 2] = (v >>> 8) & 0xff; arr[off + 3] = v & 0xff;
}
function readU32(arr, off) {
  return ((arr[off] << 24) | (arr[off + 1] << 16) | (arr[off + 2] << 8) | arr[off + 3]) >>> 0;
}

// per-chunk AES-GCM box (v3)
function ivFor(prefix, counter) {
  const iv = new Uint8Array(12);
  iv.set(prefix, 0);
  writeU32(iv, 8, counter >>> 0);
  return iv;
}
function aadFor(counter, isLast) {
  const a = new Uint8Array(5);
  writeU32(a, 0, counter >>> 0);
  a[4] = isLast ? 1 : 0;
  return a;
}
async function encChunk(key, prefix, counter, isLast, plain) {
  return new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: ivFor(prefix, counter), additionalData: aadFor(counter, isLast) }, key, plain));
}
async function decChunk(key, prefix, counter, isLast, cipher) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivFor(prefix, counter), additionalData: aadFor(counter, isLast) }, key, cipher));
  } catch {
    throw new Error('WRONG_PASSWORD');
  }
}

// ---------- In-memory format (v1/v2) ----------
async function encryptFiles(files, password) {
  if (files.length > 65535) throw new Error('Too many files (max 65,535)');
  const salt = rand(16);
  const iv = rand(12);
  const key = await deriveKey(password, salt);

  const metas = [];
  let total = 2;
  for (const f of files) {
    const nameBytes = new TextEncoder().encode(entryName(f));
    if (nameBytes.length > 65535) throw new Error('Filename is too long: ' + f.name);
    if (f.size > 0xffffffff) throw new Error('File too large (max 4 GB): ' + f.name);
    metas.push(nameBytes);
    total += 2 + nameBytes.length + 4 + f.size;
  }

  const plain = new Uint8Array(total);
  let o = 0;
  plain[o++] = (files.length >> 8) & 0xff;
  plain[o++] = files.length & 0xff;
  for (let i = 0; i < files.length; i++) {
    const nameBytes = metas[i];
    plain[o++] = (nameBytes.length >> 8) & 0xff;
    plain[o++] = nameBytes.length & 0xff;
    plain.set(nameBytes, o); o += nameBytes.length;
    writeU32(plain, o, files[i].size); o += 4;
    plain.set(new Uint8Array(await files[i].arrayBuffer()), o); o += files[i].size;
  }

  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));

  const out = new Uint8Array(5 + 16 + 12 + cipher.length);
  o = 0;
  out.set(MAGIC_V2, o); o += 5;
  out.set(salt, o); o += 16;
  out.set(iv, o); o += 12;
  out.set(cipher, o);

  return { blob: new Blob([out], { type: 'application/octet-stream' }), name: vaultName(files) };
}

// returns [{name, blob}, ...]
async function decryptFile(file, password) {
  const buf = new Uint8Array(await file.arrayBuffer());
  const headLen = 5 + 16 + 12;
  if (buf.length < headLen + 16) throw new Error('BAD_FORMAT');
  const v1 = matchMagic(buf, MAGIC_V1);
  const v2 = matchMagic(buf, MAGIC_V2);
  if (!v1 && !v2) throw new Error('BAD_FORMAT');

  const salt = buf.slice(5, 21);
  const iv = buf.slice(21, headLen);
  const cipher = buf.slice(headLen);

  const key = await deriveKey(password, salt);
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher));
  } catch {
    throw new Error('WRONG_PASSWORD');
  }

  if (v1) {
    const nameLen = (plain[0] << 8) | plain[1];
    if (2 + nameLen > plain.length) throw new Error('BAD_FORMAT');
    const name = new TextDecoder().decode(plain.slice(2, 2 + nameLen));
    return [{ name: name || 'decrypted_file', blob: new Blob([plain.slice(2 + nameLen)]) }];
  }

  const entries = [];
  let o = 0;
  const count = (plain[o] << 8) | plain[o + 1]; o += 2;
  for (let i = 0; i < count; i++) {
    if (o + 2 > plain.length) throw new Error('BAD_FORMAT');
    const nameLen = (plain[o] << 8) | plain[o + 1]; o += 2;
    if (o + nameLen + 4 > plain.length) throw new Error('BAD_FORMAT');
    const name = new TextDecoder().decode(plain.slice(o, o + nameLen)); o += nameLen;
    const size = readU32(plain, o); o += 4;
    if (o + size > plain.length) throw new Error('BAD_FORMAT');
    entries.push({ name: name || 'file_' + (i + 1), blob: new Blob([plain.slice(o, o + size)]) }); o += size;
  }
  if (!entries.length) throw new Error('BAD_FORMAT');
  return entries;
}

function vaultName(files) {
  if (files.length === 1) {
    return (entryName(files[0]).split('/').pop().replace(/\.[^.]+$/, '') || 'file') + EXT;
  }
  const d = new Date();
  const p2 = (x) => String(x).padStart(2, '0');
  return 'vault-' + d.getFullYear() + p2(d.getMonth() + 1) + p2(d.getDate()) +
         '-' + p2(d.getHours()) + p2(d.getMinutes()) + EXT;
}

// ---------- Streaming format (v3) ----------
// Yield successive Uint8Arrays of up to chunkSize bytes across the
// concatenated stream of all files, reading each file lazily by slices.
async function* streamChunks(files, chunkSize) {
  let buf = new Uint8Array(0);
  for (const f of files) {
    let pos = 0;
    while (pos < f.size) {
      const need = chunkSize - buf.length;
      const take = Math.min(need, f.size - pos);
      const piece = new Uint8Array(await f.slice(pos, pos + take).arrayBuffer());
      pos += take;
      if (buf.length === 0 && piece.length === chunkSize) {
        yield piece;                       // fast path: aligned full chunk, no copy
      } else {
        const nb = new Uint8Array(buf.length + piece.length);
        nb.set(buf); nb.set(piece, buf.length);
        buf = nb;
        if (buf.length === chunkSize) { yield buf; buf = new Uint8Array(0); }
      }
    }
  }
  if (buf.length > 0) yield buf;
}

async function encryptStreaming(files, password, writable, onProgress) {
  const total = files.reduce((s, f) => s + f.size, 0);
  const salt = rand(16);
  const prefix = rand(8);
  const key = await deriveKey(password, salt);

  const manifestObj = {
    v: 3, chunkSize: CHUNK_SIZE, totalSize: total,
    files: files.map(f => ({ name: entryName(f), size: f.size })),
  };
  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifestObj));
  const manifestCipher = await encChunk(key, prefix, 0, false, manifestBytes);

  const header = new Uint8Array(5 + 16 + 8 + 4 + 4);
  let o = 0;
  header.set(MAGIC_V3, o); o += 5;
  header.set(salt, o); o += 16;
  header.set(prefix, o); o += 8;
  writeU32(header, o, CHUNK_SIZE); o += 4;
  writeU32(header, o, manifestCipher.length); o += 4;
  await writable.write(header);
  await writable.write(manifestCipher);

  const totalChunks = total === 0 ? 0 : Math.ceil(total / CHUNK_SIZE);
  let counter = 0, done = 0;
  for await (const chunk of streamChunks(files, CHUNK_SIZE)) {
    counter++;
    const cipher = await encChunk(key, prefix, counter, counter === totalChunks, chunk);
    await writable.write(cipher);
    done += chunk.length;
    if (onProgress) onProgress(done, total);
  }
  await writable.close();
}

// Reads a v3 vault and writes the recovered files into dirHandle.
async function decryptStreaming(file, password, dirHandle, onProgress) {
  const fixed = 5 + 16 + 8 + 4 + 4;
  const header = new Uint8Array(await file.slice(0, fixed).arrayBuffer());
  if (header.length < fixed || !matchMagic(header, MAGIC_V3)) throw new Error('BAD_FORMAT');
  const salt = header.slice(5, 21);
  const prefix = header.slice(21, 29);
  const chunkSize = readU32(header, 29);
  const manifestLen = readU32(header, 33);
  if (chunkSize === 0 || chunkSize > 0x10000000 || manifestLen === 0 || fixed + manifestLen > file.size) {
    throw new Error('BAD_FORMAT');
  }

  const key = await deriveKey(password, salt);
  const manifestCipher = new Uint8Array(await file.slice(fixed, fixed + manifestLen).arrayBuffer());
  const manifestBytes = await decChunk(key, prefix, 0, false, manifestCipher); // throws WRONG_PASSWORD
  let manifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  } catch {
    throw new Error('BAD_FORMAT');
  }
  const files = manifest.files || [];
  const total = manifest.totalSize || 0;

  // Router: write the decrypted stream into output files by size, creating
  // sub-directories from any "folder/name" paths.
  let fi = -1, writable = null, rem = 0;
  async function openNext() {
    if (writable) await writable.close();
    fi++;
    if (fi >= files.length) { writable = null; return; }
    writable = await openOutputFile(dirHandle, files[fi].name || ('file_' + (fi + 1)));
    rem = files[fi].size;
    if (rem === 0) await openNext();       // empty file: created, move on
  }
  async function writeBytes(bytes) {
    let off = 0;
    while (off < bytes.length) {
      if (!writable) throw new Error('BAD_FORMAT'); // more data than the manifest declared
      const take = Math.min(rem, bytes.length - off);
      await writable.write(bytes.subarray(off, off + take));
      off += take; rem -= take;
      if (rem === 0) await openNext();
    }
  }
  await openNext();

  let pos = fixed + manifestLen;
  const totalChunks = total === 0 ? 0 : Math.ceil(total / chunkSize);
  let done = 0;
  for (let i = 1; i <= totalChunks; i++) {
    const plen = Math.min(chunkSize, total - (i - 1) * chunkSize);
    const clen = plen + 16; // + GCM tag
    const cipher = new Uint8Array(await file.slice(pos, pos + clen).arrayBuffer());
    if (cipher.length !== clen) throw new Error('BAD_FORMAT'); // truncated
    const plain = await decChunk(key, prefix, i, i === totalChunks, cipher);
    await writeBytes(plain);
    pos += clen; done += plen;
    if (onProgress) onProgress(done, total);
  }
  while (writable) await openNext(); // close last file + any trailing empties
  return { count: files.length, total };
}

async function openOutputFile(dirHandle, name) {
  const parts = name.split('/').filter(p => p && p !== '.' && p !== '..');
  let dir = dirHandle;
  for (let i = 0; i < parts.length - 1; i++) {
    dir = await dir.getDirectoryHandle(parts[i], { create: true });
  }
  const leaf = parts[parts.length - 1] || 'file';
  const fh = await dir.getFileHandle(leaf, { create: true });
  return await fh.createWritable();
}

// ---------- Download (in-memory results) ----------
function safeName(name) {
  return name.replace(/[\/\\]+/g, '_'); // browsers can't create folders on plain download
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

// CRC32 (table-less); ZIP requires a per-entry checksum.
function crc32(bytes) {
  let crc = ~0;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1));
  }
  return (~crc) >>> 0;
}

// Minimal store-only (no compression) ZIP writer. 32-bit; fine under 4 GB
// (in-memory results come from v2 vaults capped at 512 MB). ponytail: store, not deflate.
async function buildZip(entries) {
  const enc = new TextEncoder();
  const parts = [], central = [];
  let offset = 0;
  for (const en of entries) {
    const name = enc.encode(safeName(en.name));
    const data = new Uint8Array(await en.blob.arrayBuffer());
    const crc = crc32(data);

    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true);   // local file header sig
    lh.setUint16(4, 20, true);           // version needed
    lh.setUint16(6, 0x0800, true);       // flags: UTF-8 filename
    lh.setUint16(8, 0, true);            // method: store
    lh.setUint32(14, crc, true);
    lh.setUint32(18, data.length, true); // compressed size
    lh.setUint32(22, data.length, true); // uncompressed size
    lh.setUint16(26, name.length, true);
    parts.push(new Uint8Array(lh.buffer), name, data);

    const cd = new DataView(new ArrayBuffer(46));
    cd.setUint32(0, 0x02014b50, true);   // central directory sig
    cd.setUint16(4, 20, true);           // version made by
    cd.setUint16(6, 20, true);           // version needed
    cd.setUint16(8, 0x0800, true);       // flags: UTF-8 filename
    cd.setUint32(16, crc, true);
    cd.setUint32(20, data.length, true);
    cd.setUint32(24, data.length, true);
    cd.setUint16(28, name.length, true);
    cd.setUint32(42, offset, true);      // offset of local header
    central.push(new Uint8Array(cd.buffer), name);

    offset += 30 + name.length + data.length;
  }

  let cdSize = 0;
  for (const c of central) cdSize += c.length;
  const eo = new DataView(new ArrayBuffer(22));
  eo.setUint32(0, 0x06054b50, true);          // end of central directory sig
  eo.setUint16(8, entries.length, true);      // entries on this disk
  eo.setUint16(10, entries.length, true);     // total entries
  eo.setUint32(12, cdSize, true);
  eo.setUint32(16, offset, true);             // central directory offset
  return new Blob([...parts, ...central, new Uint8Array(eo.buffer)], { type: 'application/zip' });
}

function zipName() {
  const base = pickedFiles[0] ? safeName(pickedFiles[0].name).replace(/\.nnnn$/i, '') : '';
  return (base || 'files') + '.zip';
}

async function downloadAll() {
  dlAllBtn.disabled = true;
  showStatus('busy', '<span class="spinner"></span>Packaging ' + decrypted.length + ' files into a .zip...');
  await new Promise(r => setTimeout(r, 60)); // let the spinner paint before the heavy work
  try {
    const name = zipName();
    downloadBlob(await buildZip(decrypted), name);
    showStatus('ok', '✅ Downloaded <b>' + escapeHtml(name) + '</b>' +
      (isIOS() ? '<br>📱 On iPhone, find it in the Files app → Downloads' : ''));
  } catch (e) { reportError(e); } finally { dlAllBtn.disabled = false; }
}

// ---------- Main action ----------
async function run() {
  if (!pickedFiles.length) return;
  const pw = pwInput.value;

  if (mode === 'enc') {
    if (pw !== pw2Input.value) { showStatus('err', '❌ Passwords do not match'); return; }
    if (pw.length < 6) { showStatus('err', '❌ Password is too short (at least 6 characters)'); return; }
    const total = pickedFiles.reduce((s, f) => s + f.size, 0);
    if (total > STREAM_THRESHOLD) return runEncryptStreaming(pw, total);
    return runEncryptInMemory(pw);
  }

  // decrypt: route by the vault's magic bytes
  let magic;
  try {
    magic = new Uint8Array(await pickedFiles[0].slice(0, 5).arrayBuffer());
  } catch (e) { reportError(e); return; }
  if (matchMagic(magic, MAGIC_V3)) return runDecryptStreaming(pw);
  return runDecryptInMemory(pw);
}

async function runEncryptInMemory(pw) {
  goBtn.disabled = true;
  clearResults();
  showStatus('busy', '<span class="spinner"></span>Encrypting... keep this page open');
  await new Promise(r => setTimeout(r, 60)); // let the spinner paint
  try {
    const result = await encryptFiles(pickedFiles, pw);
    downloadBlob(result.blob, result.name);
    showStatus('ok',
      '✅ Encrypted ' + pickedFiles.length + ' file' + (pickedFiles.length > 1 ? 's' : '') +
      ' into <b>' + escapeHtml(result.name) + '</b>' +
      (isIOS() ? '<br>📱 On iPhone, find it in the Files app → Downloads' : ''));
    resetPasswords();
  } catch (e) { reportError(e); } finally { updateGo(); }
}

async function runEncryptStreaming(pw, total) {
  if (!fsaAvailable()) {
    showStatus('err', '❌ This is over ' + fmtSize(STREAM_THRESHOLD) +
      ' — large vaults need a computer running Chrome or Edge (not supported on iPhone).');
    return;
  }
  let handle;
  try {
    handle = await window.showSaveFilePicker({
      suggestedName: vaultName(pickedFiles),
      types: [{ description: 'FileVault vault', accept: { 'application/octet-stream': [EXT] } }],
    });
  } catch (e) {
    if (e && e.name === 'AbortError') return; // user cancelled the dialog
    reportError(e); return;
  }

  goBtn.disabled = true;
  clearResults();
  showStatus('busy', '<span class="spinner"></span>Encrypting to disk... keep this page open');
  showProgress(0, total);
  try {
    const writable = await handle.createWritable();
    await encryptStreaming(pickedFiles, pw, writable, setProgress);
    hideProgress();
    showStatus('ok', '✅ Encrypted ' + pickedFiles.length + ' file' + (pickedFiles.length > 1 ? 's' : '') +
      ' (' + fmtSize(total) + ') into <b>' + escapeHtml(handle.name) + '</b>');
    resetPasswords();
  } catch (e) {
    hideProgress();
    try { if (handle.remove) await handle.remove(); } catch { /* best-effort cleanup of partial file */ }
    reportError(e);
  } finally { updateGo(); }
}

async function runDecryptInMemory(pw) {
  goBtn.disabled = true;
  clearResults();
  showStatus('busy', '<span class="spinner"></span>Decrypting... keep this page open');
  await new Promise(r => setTimeout(r, 60));
  try {
    const entries = await decryptFile(pickedFiles[0], pw);
    if (entries.length === 1) {
      downloadBlob(entries[0].blob, safeName(entries[0].name));
      showStatus('ok', '✅ Decrypted! Downloading <b>' + escapeHtml(entries[0].name) + '</b>' +
        (isIOS() ? '<br>📱 On iPhone, find it in the Files app → Downloads' : ''));
    } else {
      showStatus('ok', '✅ Decrypted <b>' + entries.length + ' files</b> — save them below' +
        (isIOS() ? '<br>📱 Files are saved to the Files app → Downloads' : ''));
      showResults(entries);
    }
    resetPasswords();
  } catch (e) { reportError(e); } finally { updateGo(); }
}

async function runDecryptStreaming(pw) {
  if (!fsaAvailable()) {
    showStatus('err', '❌ This is a large (streamed) vault — open it on a computer running Chrome or Edge.');
    return;
  }
  let dirHandle;
  try {
    dirHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
  } catch (e) {
    if (e && e.name === 'AbortError') return; // user cancelled
    reportError(e); return;
  }

  goBtn.disabled = true;
  clearResults();
  showStatus('busy', '<span class="spinner"></span>Decrypting to the chosen folder...');
  showProgress(0, pickedFiles[0].size);
  try {
    const { count } = await decryptStreaming(pickedFiles[0], pw, dirHandle, setProgress);
    hideProgress();
    showStatus('ok', '✅ Decrypted <b>' + count + ' file' + (count > 1 ? 's' : '') + '</b> into the chosen folder');
    resetPasswords();
  } catch (e) { hideProgress(); reportError(e); } finally { updateGo(); }
}

function resetPasswords() {
  pwInput.value = ''; pw2Input.value = '';
  strengthBar.style.width = '0%';
}

function reportError(e) {
  if (e && e.message === 'WRONG_PASSWORD') {
    showStatus('err', '❌ Wrong password, or the file was modified/corrupted');
  } else if (e && e.message === 'BAD_FORMAT') {
    showStatus('err', '❌ This is not a ' + EXT + ' file created by FileVault');
  } else {
    showStatus('err', '❌ Something went wrong: ' + escapeHtml((e && e.message) || String(e)));
  }
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function isIOS() {
  return /iPhone|iPad|iPod/.test(navigator.userAgent) ||
    (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
}

// ---------- Events ----------
tabEnc.addEventListener('click', () => setMode('enc'));
tabDec.addEventListener('click', () => setMode('dec'));

drop.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) addFiles(fileInput.files);
  fileInput.value = '';
});
pickFolderBtn.addEventListener('click', () => folderInput.click());
folderInput.addEventListener('change', () => {
  if (folderInput.files.length) addFiles(folderInput.files);
  folderInput.value = '';
});
clearAllBtn.addEventListener('click', () => { clearPicked(); hideStatus(); hideProgress(); });
dlAllBtn.addEventListener('click', downloadAll);

['dragover', 'dragenter'].forEach(ev =>
  drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('hover'); }));
['dragleave', 'drop'].forEach(ev =>
  drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('hover'); }));
drop.addEventListener('drop', e => {
  if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files);
});

togglePw.addEventListener('click', () => {
  const show = pwInput.type === 'password';
  pwInput.type = show ? 'text' : 'password';
  pw2Input.type = pwInput.type;
  togglePw.textContent = show ? '🙈' : '👁️';
});

pwInput.addEventListener('input', () => {
  updateGo();
  if (mode === 'enc') {
    const s = pwStrength(pwInput.value);
    strengthBar.style.width = (s * 20) + '%';
    strengthBar.style.background = s <= 2 ? 'var(--red)' : s <= 3 ? '#fbbf24' : 'var(--green)';
  }
});
pw2Input.addEventListener('input', updateGo);

goBtn.addEventListener('click', run);

[pwInput, pw2Input].forEach(inp => inp.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !goBtn.disabled) run();
}));

// ---------- PWA ----------
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => { /* still works on plain http localhost */ });
}

setMode('enc');
