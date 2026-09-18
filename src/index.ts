export { initBackend } from './backend';
export type { Group, Point } from './backend';

export { Systems, Algorithms } from './enums';
export type { System, Algorithm } from './types';

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
  unpackScalar,
  unpackPoint,
} from './secrets';

export { shareSecret } from './dealer';
export type { ShamirSharing, SecretShare, SecretPacket, PublicShare } from './dealer';

export {
  extractPublicShare,
  verifyFeldmanCommitments,
  verifyPedersenCommitments,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
} from './shareholder';
export type { SchnorrPacket } from './shareholder';

export {
  computeLambda,
  combineSecretShares,
  combinePublicShares,
  parseSchnorrPacket,
  recoverPublic,
} from './combiner';
export type { Nonces } from './combiner';

export type { NizkProof } from './nizk';

export {
  BadGroupError,
  ShamirError,
  InvalidSecret,
  InvalidSecretShare,
  InvalidPublicShare,
  InvalidInput,
} from './errors';
