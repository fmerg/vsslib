import {
  Modular,
  Elliptic,
  Algorithms,
  AesModes,
  AsymmetricModes,
  Encodings,
} from './enums';

export type Label =
  | Modular.BITS_2048
  | Modular.BITS_4096
  | Elliptic.ED25519
  | Elliptic.ED448
  | Elliptic.JUBJUB;

export type Algorithm =
  | Algorithms.SHA224
  | Algorithms.SHA256
  | Algorithms.SHA384
  | Algorithms.SHA512
  | Algorithms.SHA3_224
  | Algorithms.SHA3_256
  | Algorithms.SHA3_384
  | Algorithms.SHA3_512;

export type AesMode =
  | AesModes.AES_256_CBC
  | AesModes.AES_256_CFB
  | AesModes.AES_256_OFB
  | AesModes.AES_256_CTR
  | AesModes.AES_256_GCM;

export type AsymmetricMode =
  | AsymmetricModes.ELGAMAL
  | AsymmetricModes.KEM
  | AsymmetricModes.IES;

export type Encoding =
  | Encodings.HEX
  | Encodings.BASE64;
