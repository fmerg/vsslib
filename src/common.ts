/** Byte "canonical" representation of a nested structure with string keys and
 * uint8 arrays as leaf values. Used in making structures of the above type
 * amenable to cryptographic operations (e.g., signing ciphertexts). Equivalent
 * to the following procedure:
 * 1. Sort keys recursively
 * 2. Encode leaf values as base64
 * 3. Dump with double quotes, no newlines and zero indentation
 * 4. Return bytes of dumped string
 */
export const toCanonical = (obj: object): Uint8Array => Buffer.from(JSON.stringify(
  obj, (key: string, value: any) => value instanceof Uint8Array ?
    Buffer.from(value).toString('base64') :
    Object.keys(value).sort().reduce(
      (sorted: any, key: any) => {
        sorted[key] = value[key];
        return sorted
      }, {}
    )
  )
)

/** Recovers the original structure from its "canonical" byte representation */
export const fromCanonical = (repr: Uint8Array) => JSON.parse(
  Buffer.from(repr).toString(),
  (key: string, value: object | string) =>
    typeof value === 'string' ?
    Uint8Array.from(Buffer.from(value, 'base64')) :
    value
)

/** Secure constant-time comparison of byte arrays */
export const ctEqualBuffer = (a: Uint8Array, b: Uint8Array) => {
  const minLength = Math.min(a.length, b.length);
  let flag = true;
  for (let i = 0; i < minLength; i++) flag &&= a[i] == b[i];
  flag &&= a.length == b.length;
  return flag;
}
