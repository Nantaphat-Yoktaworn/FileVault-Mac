// Round-trip tests for the .nnnn format — same logic as app.js
// Run: node test/roundtrip.test.mjs
const MAGIC_V1 = new TextEncoder().encode('NNNN1');
const MAGIC_V2 = new TextEncoder().encode('NNNN2');
const PBKDF2_ITERS = 600000;

async function deriveKey(password, salt) {
  const raw = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function seal(plain, password, magic) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain));
  const out = new Uint8Array(5 + 16 + 12 + cipher.length);
  out.set(magic, 0); out.set(salt, 5); out.set(iv, 21); out.set(cipher, 33);
  return out;
}

// v2 encrypt: entries = [{name, data}]
async function encryptV2(entries, password) {
  let total = 2;
  const metas = entries.map(e => new TextEncoder().encode(e.name));
  for (let i = 0; i < entries.length; i++) total += 2 + metas[i].length + 4 + entries[i].data.length;
  const plain = new Uint8Array(total);
  let o = 0;
  plain[o++] = (entries.length >> 8) & 0xff;
  plain[o++] = entries.length & 0xff;
  for (let i = 0; i < entries.length; i++) {
    const nb = metas[i], d = entries[i].data;
    plain[o++] = (nb.length >> 8) & 0xff;
    plain[o++] = nb.length & 0xff;
    plain.set(nb, o); o += nb.length;
    plain[o++] = (d.length >>> 24) & 0xff;
    plain[o++] = (d.length >>> 16) & 0xff;
    plain[o++] = (d.length >>> 8) & 0xff;
    plain[o++] = d.length & 0xff;
    plain.set(d, o); o += d.length;
  }
  return seal(plain, password, MAGIC_V2);
}

// v1 encrypt (legacy single-file format)
async function encryptV1(name, data, password) {
  const nb = new TextEncoder().encode(name);
  const plain = new Uint8Array(2 + nb.length + data.length);
  plain[0] = (nb.length >> 8) & 0xff;
  plain[1] = nb.length & 0xff;
  plain.set(nb, 2);
  plain.set(data, 2 + nb.length);
  return seal(plain, password, MAGIC_V1);
}

const matchMagic = (buf, m) => m.every((b, i) => buf[i] === b);

// decrypt: returns [{name, data}]
async function decrypt(buf, password) {
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
  } catch { throw new Error('WRONG_PASSWORD'); }

  if (v1) {
    const nameLen = (plain[0] << 8) | plain[1];
    return [{ name: new TextDecoder().decode(plain.slice(2, 2 + nameLen)), data: plain.slice(2 + nameLen) }];
  }
  const entries = [];
  let o = 0;
  const count = (plain[o] << 8) | plain[o + 1]; o += 2;
  for (let i = 0; i < count; i++) {
    const nameLen = (plain[o] << 8) | plain[o + 1]; o += 2;
    const name = new TextDecoder().decode(plain.slice(o, o + nameLen)); o += nameLen;
    const size = ((plain[o] << 24) | (plain[o + 1] << 16) | (plain[o + 2] << 8) | plain[o + 3]) >>> 0; o += 4;
    if (o + size > plain.length) throw new Error('BAD_FORMAT');
    entries.push({ name, data: plain.slice(o, o + size) }); o += size;
  }
  return entries;
}

const assert = (cond, msg) => { if (!cond) { console.error('❌ FAIL:', msg); process.exit(1); } console.log('✅', msg); };
const randBytes = (n) => {
  const a = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(a.subarray(i, i + 65536));
  return a;
};
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// 1. multi-file vault round-trip (emoji filename to exercise UTF-8, folder path, binary data)
const files = [
  { name: 'my cat 🐱.jpg', data: randBytes(1024 * 128) },
  { name: 'docs/notes.txt', data: new TextEncoder().encode('hello vault') },
  { name: 'empty.bin', data: new Uint8Array(0) },
];
const enc = await encryptV2(files, 'p@ssw0rd 🔑123');
const dec = await decrypt(enc, 'p@ssw0rd 🔑123');
assert(dec.length === 3, 'vault holds 3 files');
assert(dec.every((e, i) => e.name === files[i].name), 'all filenames restored (UTF-8 + folder path)');
assert(dec.every((e, i) => sameBytes(e.data, files[i].data)), 'all payloads match byte-for-byte (incl. 0-byte file)');

// 2. wrong password must throw WRONG_PASSWORD
let threw = '';
try { await decrypt(enc, 'wrong-password'); } catch (e) { threw = e.message; }
assert(threw === 'WRONG_PASSWORD', 'wrong password → rejected (WRONG_PASSWORD)');

// 3. tampering with a single byte must fail decryption
const tampered = enc.slice();
tampered[tampered.length - 5] ^= 0xff;
threw = '';
try { await decrypt(tampered, 'p@ssw0rd 🔑123'); } catch (e) { threw = e.message; }
assert(threw === 'WRONG_PASSWORD', 'file tampered by 1 byte → rejected');

// 4. garbage input must be BAD_FORMAT
threw = '';
try { await decrypt(new Uint8Array([1, 2, 3]), 'x'); } catch (e) { threw = e.message; }
assert(threw === 'BAD_FORMAT', 'not a .nnnn file → BAD_FORMAT');

// 5. legacy v1 files still decrypt (backward compatibility)
const v1data = randBytes(4096);
const encV1 = await encryptV1('old-format.pdf', v1data, 'legacy-pw');
const decV1 = await decrypt(encV1, 'legacy-pw');
assert(decV1.length === 1 && decV1[0].name === 'old-format.pdf' && sameBytes(decV1[0].data, v1data),
  'v1 (NNNN1) file still decrypts');

// 6. single-file v2 vault works too
const encOne = await encryptV2([{ name: 'one.txt', data: new TextEncoder().encode('solo') }], 'pw1234');
const decOne = await decrypt(encOne, 'pw1234');
assert(decOne.length === 1 && new TextDecoder().decode(decOne[0].data) === 'solo', 'single-file v2 vault round-trips');

console.log('\n🎉 all tests passed');
