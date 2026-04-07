import { ArithmeticError, BadModulusError, InverseNotExists } from './errors';

const __hexLen  = [0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4];


const nrBits = (num: bigint): number => {
  const numHex = num.toString(16);
  return (numHex.length - 1) * 4 + __hexLen[parseInt(numHex[0], 16)];
}

const nrBytes = (num: bigint): number => {
  const nr = Math.floor((nrBits(num) - 1) / 8) + 1;
  return nr == 0 ? 1 : nr;
}


/** little-endian bytestring to big integer */
export const leBuff2Int = (buff: Uint8Array): bigint => {
  let num = 0n;
  let i = 0;
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength);
  while (i < buff.length) {
    if (i + 4 <= buff.length) {
      num += BigInt(view.getUint32(i, true)) << BigInt(i * 8);
      i += 4;
    } else if (i + 2 <= buff.length) {
      num += BigInt(view.getUint16(i, true)) << BigInt(i * 8);
      i += 2;
    } else {
      num += BigInt(view.getUint8(i)) << BigInt(i * 8);
      i += 1;
    }
  }
  return num;
}


/** big integer to little-endian bytestring, zero-padded to `byteLength` if given */
export const leInt2Buff = (num: bigint, byteLength?: number) => {
  const minLength = nrBytes(num);
  if (byteLength !== undefined && byteLength < minLength) throw new ArithmeticError(
    `Integer does not fit in ${byteLength} bytes`
  );
  const len = byteLength ?? minLength;
  const buff = new Uint8Array(len);
  const view = new DataView(buff.buffer);

  let i = 0;
  let r = num as bigint;
  while (i < len) {
    if (i + 4 <= len) {
      view.setUint32(i, Number(r & 0xffffffffn), true);
      i += 4;
      r = r >> 32n;
    } else if (i + 2 <= len) {
      view.setUint16(i, Number(r & 0xffffn), true);
      i += 2;
      r = r >> 16n;
    } else {
      view.setUint8(i, Number(r & 0xffn));
      i += 1;
      r = r >> 8n;
    }
  }
  return buff;
}


/** Modulo operation. Takes care to give non-negative results */
export const mod = (m: bigint, n: bigint): bigint => {
  if (n < 2) throw new BadModulusError(
    `Modulus must be > 2: ${n}`
  );

  const r = m % n;
  return r >= 0n ? r : (r + n) % n;
}


/** Createst Common Divisor (extended euclidean algorithm) */
export const gcd = (a: bigint, b: bigint): { x: bigint, y: bigint, g: bigint } => {
  if (!(a > 0n && b > 0n))
    throw new ArithmeticError('Non-positive inputs');

  let [x, y, u, v] = [0n, 1n, 1n, 0n];
  while (a > 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - (u * q);
    const n = y - (v * q);
    b = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }
  return { x, y, g: b };
}


/** Modular muptiplicative inverse operation */
export const modInv = (m: bigint, n: bigint): bigint => {
  const a = mod(m, n);
  if (!(a > 0n)) throw new InverseNotExists(
    `No inverse exists for provided modulo`
  );

  const { x, g } = gcd(a, n);
  if (g !== 1n) throw new InverseNotExists(
    `No inverse exists for provided modulo`
  );

  return mod(x, n);
}
