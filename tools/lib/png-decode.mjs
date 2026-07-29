// minimal PNG decoder (node:zlib only) — enough for a qlmanage thumbnail
import { readFileSync } from 'node:fs';
import { inflateSync } from 'node:zlib';

export function decodePNG(path) {
  const b = readFileSync(path);
  let off = 8, w = 0, h = 0, depth = 0, ctype = 0;
  const idat = [];
  while (off < b.length) {
    const len = b.readUInt32BE(off);
    const type = b.toString('ascii', off + 4, off + 8);
    const data = b.subarray(off + 8, off + 8 + len);
    if (type === 'IHDR') { w = data.readUInt32BE(0); h = data.readUInt32BE(4); depth = data[8]; ctype = data[9]; }
    else if (type === 'IDAT') idat.push(data);
    else if (type === 'IEND') break;
    off += 12 + len;
  }
  if (depth !== 8) throw new Error('bit depth ' + depth + ' unsupported');
  const ch = { 0: 1, 2: 3, 4: 2, 6: 4 }[ctype];
  if (!ch) throw new Error('color type ' + ctype + ' unsupported');
  const raw = inflateSync(Buffer.concat(idat));
  const stride = w * ch;
  const out = Buffer.alloc(h * stride);
  const paeth = (a, bb, c) => { const p = a + bb - c, pa = Math.abs(p - a), pb = Math.abs(p - bb), pc = Math.abs(p - c); return pa <= pb && pa <= pc ? a : pb <= pc ? bb : c; };
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)];
    const line = raw.subarray(y * (stride + 1) + 1, y * (stride + 1) + 1 + stride);
    for (let x = 0; x < stride; x++) {
      const a = x >= ch ? out[y * stride + x - ch] : 0;
      const up = y > 0 ? out[(y - 1) * stride + x] : 0;
      const ul = (x >= ch && y > 0) ? out[(y - 1) * stride + x - ch] : 0;
      let v = line[x];
      if (f === 1) v += a; else if (f === 2) v += up; else if (f === 3) v += (a + up) >> 1; else if (f === 4) v += paeth(a, up, ul);
      out[y * stride + x] = v & 0xff;
    }
  }
  // ink = dark AND opaque
  const ink = (x, y) => {
    const i = y * stride + x * ch;
    const alpha = ch === 4 ? out[i + 3] : ch === 2 ? out[i + 1] : 255;
    if (alpha < 128) return false;
    const lum = ch >= 3 ? (out[i] * 0.299 + out[i + 1] * 0.587 + out[i + 2] * 0.114) : out[i];
    return lum < 140;
  };
  return { w, h, ink };
}
