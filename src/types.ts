import { Elliptic, Algorithms } from './enums';
import type { NizkProof } from './nizk';

/** Name of a built-in system; see {@link Systems} */
export type System = Elliptic;

/** Hash function for NIZK challenges; see {@link Algorithms} */
export type Algorithm =
  | Algorithms.SHA224
  | Algorithms.SHA256
  | Algorithms.SHA384
  | Algorithms.SHA512
  | Algorithms.SHA3_224
  | Algorithms.SHA3_256
  | Algorithms.SHA3_384
  | Algorithms.SHA3_512;

/** Share of a secret, i.e. the sharing polynomial evaluated at `index` */
export type SecretShare = {
  /** Encoded scalar */
  value: Uint8Array,
  /** Positive integer, distinct among the shares of a sharing */
  index: number,
};

/** Public counterpart of a secret share, i.e. the generator raised to it */
export type PublicShare = {
  /** Encoded group element */
  value: Uint8Array,
  /** Index of the secret share */
  index: number,
};

/** Secret share sent by the dealer of a VSS scheme to its shareholder */
export type SecretPacket = SecretShare & {
  /** Encoded binding scalar, in Pedersen packets only */
  binding?: Uint8Array,
};

/** Public share with a proof of knowledge of its secret share, bound to its
 * index, as used in verifiable public recovery */
export type SchnorrPacket = PublicShare & {
  /** Schnorr proof of knowledge of the secret share */
  proof: NizkProof,
};
