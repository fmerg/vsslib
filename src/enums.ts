export enum Modular {
  BITS_2048 = 2048,
  BITS_4096 = 4096,
}

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
  // ...Modular,
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

export enum AesModes {
  DEFAULT     = 'aes-256-cbc',
  AES_256_CBC = 'aes-256-cbc',
  AES_256_CFB = 'aes-256-cfb',
  AES_256_OFB = 'aes-256-ofb',
  AES_256_CTR = 'aes-256-ctr',
  AES_256_GCM = 'aes-256-gcm',
}

export enum ElgamalSchemes {
  DEFAULT   = 'ies',
  PLAIN     = 'plain',
  KEM       = 'kem',
  IES       = 'ies',
}

export enum Encodings {
  HEX       = 'hex',
  BASE64    = 'base64',
}

