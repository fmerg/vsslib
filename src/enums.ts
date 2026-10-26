/** Elliptic-curve groups of the built-in backends */
export enum Elliptic {
  /** edwards25519, cofactor 8, RFC 8032 encoding */
  ED25519   = 'ed25519',
  /** edwards448, cofactor 4, RFC 8032 encoding */
  ED448     = 'ed448',
  /** Jubjub, cofactor 8, Zcash encoding */
  JUBJUB    = 'jubjub',
  /** ristretto255 over edwards25519, prime order, RFC 9496 encoding */
  RISTRETTO255 = 'ristretto255',
  /** decaf448 over edwards448, prime order, RFC 9496 encoding */
  DECAF448  = 'decaf448',
  /** secp256k1, compressed SEC1 encoding */
  SECP256K1 = 'secp256k1',
  /** NIST P-256, compressed SEC1 encoding */
  P256      = 'p256',
  /** NIST P-384, compressed SEC1 encoding */
  P384      = 'p384',
  /** NIST P-521, compressed SEC1 encoding */
  P521      = 'p521',
}

/** Names of the built-in systems, accepted by `initBackend` */
export const Systems: typeof Elliptic = {
  ...Elliptic,
}

/** Hash functions for NIZK challenges */
export enum Algorithms {
  /** Default of every operation taking an algorithm: SHA-256 */
  DEFAULT   = 'sha256',
  /** SHA-224 */
  SHA224    = 'sha224',
  /** SHA-256 */
  // eslint-disable-next-line @typescript-eslint/no-duplicate-enum-values
  SHA256    = 'sha256',
  /** SHA-384 */
  SHA384    = 'sha384',
  /** SHA-512 */
  SHA512    = 'sha512',
  /** SHA3-224 */
  SHA3_224  = 'sha3-224',
  /** SHA3-256 */
  SHA3_256  = 'sha3-256',
  /** SHA3-384 */
  SHA3_384  = 'sha3-384',
  /** SHA3-512 */
  SHA3_512  = 'sha3-512',
}
