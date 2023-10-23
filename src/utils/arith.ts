import { Messages } from './enums';

const __0n = BigInt(0);
const __1n = BigInt(1);


/** Modulo operation. Takes care to give non-negative results */
export const mod = (m: bigint, n: bigint): bigint => {
  if (n < 2) throw new Error(Messages.MODULUS_MUST_BE_GT_TWO);
  const r = m % n;
  return r >= __0n ? r : (r + n) % n;
}


/** Createst Common Divisor (extended euclidean algorithm) */
export const gcd = (a: bigint, b: bigint): { x: bigint, y: bigint, g: bigint } => {
  if (a <= __0n || b <= __0n) throw new Error(Messages.NON_POSITIVE_INPUTS);
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
  let d;
  try { d = gcd(mod(m, n), n); } catch (err: any) {
    if (err.message == Messages.NON_POSITIVE_INPUTS) throw new Error(
      Messages.INVERSE_NOT_EXISTS
    );
    else throw err;
  }
  const { x, g } = d;
  if (g !== __1n) throw new Error(Messages.INVERSE_NOT_EXISTS);
  return mod(x, n);
}

