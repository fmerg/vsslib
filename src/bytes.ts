/** Equality of byte arrays in time independent of their contents; lengths
 * are treated as public */
export function isEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  // SECURITY! no early exit, so timing reveals no matching prefix
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
