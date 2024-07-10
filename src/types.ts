import { Elliptic, Algorithms, BlockModes, ElgamalSchemes, SignatureSchemes } from 'vsslib/enums';

export type System =
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

export type BlockMode =
  | BlockModes.AES_256_CBC
  | BlockModes.AES_256_CFB
  | BlockModes.AES_256_OFB
  | BlockModes.AES_256_CTR
  | BlockModes.AES_256_GCM;

export type ElgamalScheme =
  | ElgamalSchemes.PLAIN
  | ElgamalSchemes.HYBRID
  | ElgamalSchemes.DHIES;

export type SignatureScheme =
  | SignatureSchemes.SCHNORR;
