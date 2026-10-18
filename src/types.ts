import { Elliptic, Algorithms } from './enums';
import type { NizkProof } from './nizk';

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

export type SecretShare = { value: Uint8Array, index: number };

export type PublicShare = { value: Uint8Array, index: number };

export type SecretPacket = SecretShare & { binding?: Uint8Array };

export type SchnorrPacket = PublicShare & { proof: NizkProof };
