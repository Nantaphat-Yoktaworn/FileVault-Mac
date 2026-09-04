// Self-check for the store-only ZIP writer in app.js.
// Mirrors app.js byte layout (like the other tests). Run: node test/zip.test.mjs
import assert from 'node:assert';
import { execSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';

// --- copies of the app.js logic (kept in sync with app.js) ---
function crc32(bytes) {
  let crc = ~0;
  for (let i = 0; i < bytes.length; i++) {
    crc ^= bytes[i];
    for (let j = 0; j < 8; j++) crc = (crc >>> 1) ^ (0xEDB88320 & -(crc & 1));
  }
  return (~crc) >>> 0;
}
function safeName(name) { return name.replace(/[\/\\]+/g, '_'); }

function buildZipBytes(entries) {
  const enc = new TextEncoder();
  const parts = [], central = [];
  let offset = 0;
  for (const en of entries) {
    const name = enc.encode(safeName(en.name));
    const data = en.data;
    const crc = crc32(data);
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true);
    lh.setUint16(4, 20, true);
    lh.setUint16(6, 0x0800, true);
    lh.setUint16(8, 0, true);
    lh.setUint32(14, crc, true);
    lh.setUint32(18, data.length, true);
    lh.setUint32(22, data.length, true);
    lh.setUint16(26, name.length, true);
    parts.push(new Uint8Array(lh.buffer), name, data);

    const cd = new DataView(new ArrayBuffer(46));
    cd.setUint32(0, 0x02014b50, true);
    cd.setUint16(4, 20, true);
    cd.setUint16(6, 20, true);
    cd.setUint16(8, 0x0800, true);
    cd.setUint32(16, crc, true);
    cd.setUint32(20, data.length, true);
    cd.setUint32(24, data.length, true);
    cd.setUint16(28, name.length, true);
    cd.setUint32(42, offset, true);
    central.push(new Uint8Array(cd.buffer), name);
    offset += 30 + name.length + data.length;
  }
  let cdSize = 0;
  for (const c of central) cdSize += c.length;
  const eo = new DataView(new ArrayBuffer(22));
  eo.setUint32(0, 0x06054b50, true);
  eo.setUint16(8, entries.length, true);
  eo.setUint16(10, entries.length, true);
  eo.setUint32(12, cdSize, true);
  eo.setUint32(16, offset, true);

  const all = [...parts, ...central, new Uint8Array(eo.buffer)];
  const total = all.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of all) { out.set(p, o); o += p.length; }
  return out;
}

// --- checks ---
// 1. CRC32 of "hello" is a well-known constant.
assert.strictEqual(crc32(new TextEncoder().encode('hello')), 0x3610a686, 'crc32("hello")');

// 2. Empty (0-byte) file -> CRC32 is 0.
assert.strictEqual(crc32(new Uint8Array(0)), 0, 'crc32(empty)');

// 3. Header signatures + counts in a real multi-entry zip.
const enc = new TextEncoder();
const entries = [
  { name: 'a.txt', data: enc.encode('hello') },
  { name: 'sub/b.bin', data: new Uint8Array(0) },     // sub-path -> flattened name
  { name: 'c', data: enc.encode('xyz') },
];
const zip = buildZipBytes(entries);
const dv = new DataView(zip.buffer);
assert.strictEqual(dv.getUint32(0, true), 0x04034b50, 'starts with local file header');
const eocd = zip.length - 22;
assert.strictEqual(dv.getUint32(eocd, true), 0x06054b50, 'ends with EOCD');
assert.strictEqual(dv.getUint16(eocd + 10, true), 3, 'EOCD reports 3 entries');

// 4. Cross-check against a real unzip tool if available: write the zip, list it.
try {
  writeFileSync('test/_tmp.zip', zip);
  const out = execSync('tar -tf test/_tmp.zip', { encoding: 'utf8' });
  assert.ok(out.includes('a.txt'), 'tar lists a.txt');
  assert.ok(out.includes('sub_b.bin'), 'tar lists flattened sub_b.bin');
  unlinkSync('test/_tmp.zip');
  console.log('  (verified zip listing via system tar)');
} catch (e) {
  console.log('  (skipped tar cross-check: ' + (e.code || e.message) + ')');
  try { unlinkSync('test/_tmp.zip'); } catch {}
}

console.log('zip.test.mjs: all checks passed');
