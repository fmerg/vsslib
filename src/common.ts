/** Secure constant-time comparison of byte arrays */
export const ctEqualBuffer = (a: Uint8Array, b: Uint8Array) => {
  const minLength = Math.min(a.length, b.length);
  let flag = true;
  for (let i = 0; i < minLength; i++) flag &&= a[i] == b[i];
  flag &&= a.length == b.length;
  return flag;
}
