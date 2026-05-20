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
  combinePublics,
  parseScalar,
  parsePoint,
} from './secrets';

export { shareSecret } from './dealer';
export type { ShamirSharing } from './dealer';

export {
  extractPublicShare,
  verifyFeldmanCommitments,
  verifyPedersenCommitments,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
} from './shareholder';

export { computeLambda } from './lagrange';

export {
  combineSecretShares,
  combinePublicShares,
  parseSchnorrPacket,
  recoverPublic,
} from './combiner';
export type { Nonces } from './combiner';

export type { NizkProof } from './nizk';

export {
  VssError,
  BadGroupError,
  ShamirError,
  InvalidSecret,
  InvalidSecretShare,
  InvalidPublicShare,
  InvalidInput,
} from './errors';
