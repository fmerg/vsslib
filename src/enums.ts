export enum Elliptic {
  ED25519   = 'ed25519',
  ED448     = 'ed448',
  JUBJUB    = 'jubjub',
  // SECP256K1 = 'secp256k1',
  // PALLAS    = 'pallas',
  // VESTA     = 'vesta',
  // P256      = 'p256',
  // P384      = 'p384',
  // P521      = 'p521',
  // BN254     = 'bn254',
}

export const Systems = {
  ...Elliptic,
}

export enum Algorithms {
  DEFAULT   = 'sha256',
  SHA224    = 'sha224',
  SHA256    = 'sha256',
  SHA384    = 'sha384',
  SHA512    = 'sha512',
  SHA3_224  = 'sha3-224',
  SHA3_256  = 'sha3-256',
  SHA3_384  = 'sha3-384',
  SHA3_512  = 'sha3-512',
}

// TODO: Remove cryptographically insecure block-mode
export enum BlockModes {
  DEFAULT     = 'aes-256-cbc',
  AES_256_CBC = 'aes-256-cbc',
  AES_256_CFB = 'aes-256-cfb',
  AES_256_OFB = 'aes-256-ofb',
  AES_256_CTR = 'aes-256-ctr',
  AES_256_GCM = 'aes-256-gcm',
}

export enum ElgamalSchemes {
  HYBRID    = 'hybrid',
  DEFAULT   = 'dhies',
  PLAIN     = 'plain',
  DHIES     = 'dhies',
}

export enum SignatureSchemes {
  DEFAULT   = 'schnorr',
  SCHNORR   = 'schnorr',
}
