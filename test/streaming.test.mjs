// Round-trip tests for the v3 streaming format — mirrors app.js byte layout.
// Exercises chunk boundaries that cut across file boundaries, plus the
// in-memory router that reassembles the concatenated stream into files.
// Run: node test/streaming.test.mjs
const MAGIC_V3 = new TextEncoder().encode('NNNN3');
const PBKDF2_ITERS = 600000;

async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

const writeU32 = (a, o, v) => { a[o] = (v >>> 24) & 0xff; a[o + 1] = (v >>> 16) & 0xff; a[o + 2] = (v >>> 8) & 0xff; a[o + 3] = v & 0xff; };
const readU32 = (a, o) => ((a[o] << 24) | (a[o + 1] << 16) | (a[o + 2] << 8) | a[o + 3]) >>> 0;
const ivFor = (prefix, c) => { const iv = new Uint8Array(12); iv.set(prefix, 0); writeU32(iv, 8, c >>> 0); return iv; };
const aadFor = (c, last) => { const a = new Uint8Array(5); writeU32(a, 0, c >>> 0); a[4] = last ? 1 : 0; return a; };

async function encChunk(key, prefix, c, last, plain) {
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivFor(prefix, c), additionalData: aadFor(c, last) }, key, plain));
}
async function decChunk(key, prefix, c, last, cipher) {
  try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivFor(prefix, c), additionalData: aadFor(c, last) }, key, cipher)); }
  catch { throw new Error('WRONG_PASSWORD'); }
}
const matchMagic = (buf, m) => m.every((b, i) => buf[i] === b);

function concat(parts) {
  const len = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// files = [{name, data:Uint8Array}]
async function encrypt(files, password, chunkSize) {
  const total = files.reduce((s, f) => s + f.data.length, 0);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const prefix = crypto.getRandomValues(new Uint8Array(8));
  const key = await deriveKey(password, salt);

  const manifest = new TextEncoder().encode(JSON.stringify({
    v: 3, chunkSize, totalSize: total, files: files.map(f => ({ name: f.name, size: f.data.length })),
  }));
  const manifestCipher = await encChunk(key, prefix, 0, false, manifest);

  const header = new Uint8Array(5 + 16 + 8 + 4 + 4);
  let o = 0;
  header.set(MAGIC_V3, o); o += 5;
  header.set(salt, o); o += 16;
  header.set(prefix, o); o += 8;
  writeU32(header, o, chunkSize); o += 4;
  writeU32(header, o, manifestCipher.length); o += 4;

  // concatenated data stream → chunks
  const stream = concat(files.map(f => f.data));
  const totalChunks = total === 0 ? 0 : Math.ceil(total / chunkSize);
  const parts = [header, manifestCipher];
  for (let i = 1; i <= totalChunks; i++) {
    const slice = stream.subarray((i - 1) * chunkSize, Math.min(i * chunkSize, total));
    parts.push(await encChunk(key, prefix, i, i === totalChunks, slice));
  }
  return concat(parts);
}

async function decrypt(buf, password) {
  const fixed = 5 + 16 + 8 + 4 + 4;
  if (buf.length < fixed || !matchMagic(buf, MAGIC_V3)) throw new Error('BAD_FORMAT');
  const salt = buf.slice(5, 21);
  const prefix = buf.slice(21, 29);
  const chunkSize = readU32(buf, 29);
  const manifestLen = readU32(buf, 33);
  const key = await deriveKey(password, salt);
  const manifestBytes = await decChunk(key, prefix, 0, false, buf.slice(fixed, fixed + manifestLen));
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes));
  const files = manifest.files, total = manifest.totalSize;

  // reassemble stream then split by sizes (router equivalent)
  let pos = fixed + manifestLen;
  const totalChunks = total === 0 ? 0 : Math.ceil(total / chunkSize);
  const plainParts = [];
  for (let i = 1; i <= totalChunks; i++) {
    const plen = Math.min(chunkSize, total - (i - 1) * chunkSize);
    const clen = plen + 16;
    if (pos + clen > buf.length) throw new Error('BAD_FORMAT');
    plainParts.push(await decChunk(key, prefix, i, i === totalChunks, buf.slice(pos, pos + clen)));
    pos += clen;
  }
  const stream = concat(plainParts);
  const out = [];
  let off = 0;
  for (const f of files) { out.push({ name: f.name, data: stream.slice(off, off + f.size) }); off += f.size; }
  return out;
}

const assert = (c, m) => { if (!c) { console.error('❌ FAIL:', m); process.exit(1); } console.log('✅', m); };
const randBytes = (n) => { const a = new Uint8Array(n); for (let i = 0; i < n; i += 65536) crypto.getRandomValues(a.subarray(i, i + 65536)); return a; };
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// chunkSize deliberately small (1000) so data spans many chunks AND file boundaries
const CS = 1000;
const files = [
  { name: 'my cat 🐱.jpg', data: randBytes(2300) },  // spans 3 chunks
  { name: 'docs/a.txt', data: new TextEncoder().encode('hello vault stream') },
  { name: 'empty.bin', data: new Uint8Array(0) },     // zero-length in the middle
  { name: 'big.bin', data: randBytes(4096) },         // crosses several boundaries
];
const PW = 'p@ssw0rd 🔑123';

const enc = await encrypt(files, PW, CS);
const dec = await decrypt(enc, PW);
assert(dec.length === files.length, 'all files recovered from streamed vault');
assert(dec.every((e, i) => e.name === files[i].name), 'filenames + folder paths restored');
assert(dec.every((e, i) => same(e.data, files[i].data)), 'every byte matches across chunk/file boundaries (incl. 0-byte file)');

// wrong password
let threw = '';
try { await decrypt(enc, 'nope'); } catch (e) { threw = e.message; }
assert(threw === 'WRONG_PASSWORD', 'wrong password → rejected on manifest chunk');

// tamper a data chunk byte
const tampered = enc.slice();
tampered[tampered.length - 10] ^= 0xff;
threw = '';
try { await decrypt(tampered, PW); } catch (e) { threw = e.message; }
assert(threw === 'WRONG_PASSWORD', 'tampered data chunk → rejected');

// truncate the vault (drop last 50 bytes) → must fail, never silently short
threw = '';
try { await decrypt(enc.slice(0, enc.length - 50), PW); } catch (e) { threw = e.message; }
assert(threw === 'WRONG_PASSWORD' || threw === 'BAD_FORMAT', 'truncated vault → rejected');

// reorder defense: swap two data chunks' bytes by rebuilding with wrong counter is implicit —
// here we corrupt the isLast binding by flipping a byte in the final chunk's tag region (already covered above).

// single large-ish file, exact multiple of chunk size (boundary alignment)
const aligned = [{ name: 'aligned.bin', data: randBytes(CS * 3) }];
const encA = await encrypt(aligned, PW, CS);
const decA = await decrypt(encA, PW);
assert(decA.length === 1 && same(decA[0].data, aligned[0].data), 'chunk-aligned file round-trips exactly');

// all-empty vault (totalSize 0, no data chunks)
const empties = [{ name: 'e1.txt', data: new Uint8Array(0) }, { name: 'e2.txt', data: new Uint8Array(0) }];
const encE = await encrypt(empties, PW, CS);
const decE = await decrypt(encE, PW);
assert(decE.length === 2 && decE.every(e => e.data.length === 0), 'all-empty vault round-trips');

console.log('\n🎉 all streaming tests passed');
