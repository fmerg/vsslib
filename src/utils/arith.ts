const __0n = BigInt(0);
const __1n = BigInt(1);


export const mod = (m: bigint, n: bigint): bigint => {
  const r = m % n;
  return r >= __0n ? r : n + r;
}

export const gcd = (a: bigint, b: bigint): { x: bigint, y: bigint, g: bigint } => {
  if (!(a > __0n && b > __0n)) throw new Error ('Non-positive inputs');
  let x = __0n;
  let y = __1n;
  let u = __1n;
  let v = __0n;
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

export const modInv = (m: bigint, n: bigint): bigint => {
  const { x, g } = gcd(mod(m, n), n);
  if (g !== __1n) throw new Error('No inverse exists for provided modulo');
  return mod(x, n);
}

