import { BadModulusError, InverseNotExists } from 'vsslib/errors';


const __0n = BigInt(0);
const __1n = BigInt(1);


/** Modulo operation. Takes care to give non-negative results */
export const mod = (m: bigint, n: bigint): bigint => {
  if (n < 2) throw new BadModulusError(
    `Modulus must be > 2: ${n}`
  );

  const r = m % n;
  return r >= __0n ? r : (r + n) % n;
}


/** Createst Common Divisor (extended euclidean algorithm) */
export const gcd = (a: bigint, b: bigint): { x: bigint, y: bigint, g: bigint } => {
  if (!(a > __0n && b > __0n))
    throw new Error('Non-positive inputs');

  let [x, y, u, v] = [__0n, __1n, __1n, __0n];
  while (a > __0n) {
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
  if (!(a > __0n)) throw new InverseNotExists(
    `No inverse exists for provided modulo`
  );

  const { x, g } = gcd(a, n);
  if (g !== __1n) throw new InverseNotExists(
    `No inverse exists for provided modulo`
  );

  return mod(x, n);
}
