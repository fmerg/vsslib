/**
 * Secret sharing (Shamir), verifiable secret sharing (Feldman, Pedersen) and
 * verifiable public recovery over prime-order groups. Every operation takes a
 * backend instance, e.g. from `initBackend`, and exchanges secrets, shares and
 * group elements as bytes
 *
 * @module vsslib
 */

export { initBackend } from './backend';
export type { Group, Point } from './backend';

export { Systems, Algorithms } from './enums';
export type { Elliptic } from './enums';
export type {
  System,
  Algorithm,
  SecretShare,
  PublicShare,
  SecretPacket,
  SchnorrPacket,
} from './types';

export { randomNonce } from './random';

export {
  randomSecret,
  randomPublic,
  extractPublic,
  isEqualSecret,
  isEqualPublic,
  isKeypair,
  addSecrets,
  multiplyPublics,
  parseScalar,
  parsePoint,
  shareSecret,
  combineSecretShares,
  combinePublicShares,
  createFeldmanPackets,
  verifyFeldmanCommitments,
  parseFeldmanPacket,
  derivePedersenBase,
  createPedersenPackets,
  verifyPedersenCommitments,
  parsePedersenPacket,
  createSchnorrPacket,
  parseSchnorrPacket,
  recoverPublic,
} from './operations';
export type { ShamirSharing, Nonces } from './operations';

export { computeLambda, computeLambdas } from './lagrange';

export type { NizkProof } from './nizk';

export {
  VssError,
  BadGroupError,
  ShamirError,
  InvalidSecretShare,
  InvalidPublicShare,
  InvalidInput,
} from './errors';
