const __0n = BigInt(0);
const __1n = BigInt(1);


/** Modulo operation. Takes care to give non-negative results */
export const mod = (m: bigint, n: bigint): bigint => {
  if (n < 2) throw new Error('Modulus must be > 2');
  const r = m % n;
  return r >= __0n ? r : (r + n) % n;
}


/** Createst Common Divisor (extended euclidean algorithm) */
export const gcd = (a: bigint, b: bigint): { x: bigint, y: bigint, g: bigint } => {
  if (a <= __0n || b <= __0n) throw new Error ('Non-positive inputs');
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
  try {
    d = gcd(mod(m, n), n);
  } catch (err: any) {
    if (err.message == 'Non-positive inputs') throw new Error(
      'No inverse exists for provided modulo'
    );
    else throw err;
  }
  const { x, g } = d;
  if (g !== __1n) throw new Error('No inverse exists for provided modulo');
  return mod(x, n);
}

