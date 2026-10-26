import { ArithmeticError, BadModulusError, NoInverseError } from './errors';

const __hexLen  = [0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4];


function nrBits(num: bigint): number {
  const numHex = num.toString(16);
  return (numHex.length - 1) * 4 + __hexLen[parseInt(numHex[0], 16)];
}

function nrBytes(num: bigint): number {
  const nr = Math.floor((nrBits(num) - 1) / 8) + 1;
  return nr == 0 ? 1 : nr;
}


/** little-endian bytestring to big integer */
export function leBytesToInt(buff: Uint8Array): bigint {
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
export function intToLeBytes(num: bigint, byteLength?: number) {
  // SECURITY!
  // With a given length, bound-check instead of measuring the integer, whose
  // string conversion would copy secrets to the heap in variable time
  if (byteLength !== undefined && !(0n <= num && num < 1n << BigInt(8 * byteLength)))
    throw new ArithmeticError(`Integer does not fit in ${byteLength} bytes`);
  const len = byteLength ?? nrBytes(num);
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


/** Products and sums of products are reduced modulo the order only once they
 * outgrow it by this many bits; reducing at every step is slower */
export const REDUCTION_MARGIN = 256n;


/** Modulo operation. Takes care to give non-negative results */
export function mod(m: bigint, n: bigint): bigint {
  if (n < 2) throw new BadModulusError(
    `Modulus must be > 2: ${n}`
  );

  const r = m % n;
  return r >= 0n ? r : (r + n) % n;
}


/** Createst Common Divisor (extended euclidean algorithm) */
export function gcd(a: bigint, b: bigint): { x: bigint, y: bigint, g: bigint } {
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
export function modInv(m: bigint, n: bigint): bigint {
  const a = mod(m, n);
  if (!(a > 0n)) throw new NoInverseError(
    `No inverse exists for provided modulo`
  );

  const { x, g } = gcd(a, n);
  if (g !== 1n) throw new NoInverseError(
    `No inverse exists for provided modulo`
  );

  return mod(x, n);
}


/** Modular inverses of all `values` with a single inversion (Montgomery's
 * trick). Throws NoInverseError if any of them has no inverse */
export function modInvBatch(values: bigint[], n: bigint): bigint[] {
  const k = values.length;
  const reduced = values.map(v => mod(v, n));
  // prefixes[i] is the product of the values before i
  const prefixes = new Array<bigint>(k);
  let acc = 1n;
  for (let i = 0; i < k; i++) {
    prefixes[i] = acc;
    acc = mod(acc * reduced[i], n);
  }
  // PERFORMANCE! one inversion for all values
  // The product is invertible exactly when every value is
  let inv = modInv(acc, n);
  const inverses = new Array<bigint>(k);
  for (let i = k - 1; i >= 0; i--) {
    inverses[i] = mod(inv * prefixes[i], n);
    inv = mod(inv * reduced[i], n);
  }
  return inverses;
}
