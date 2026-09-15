export { initBackend } from './backend';
export type { Group, Point } from './backend';

export { Systems, Algorithms } from './enums';
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
  addPublics,
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

export { computeLambda } from './lagrange';

export type { NizkProof } from './nizk';

export {
  VssError,
  BadGroupError,
  ShamirError,
  InvalidSecretShare,
  InvalidPublicShare,
  InvalidInput,
} from './errors';
