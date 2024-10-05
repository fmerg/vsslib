export { initBackend } from 'vsslib/backend';

export { Systems, Algorithms } from 'vsslib/enums';

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
} from 'vsslib/secrets';

export { shareSecret } from 'vsslib/dealer';

export {
  extractPublicShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
} from 'vsslib/shareholder';

export {
  computeLambda,
  combineSecretShares,
  combinePublicShares,
  parseSchnorrPacket,
  recoverPublic,
} from 'vsslib/combiner';

export {
  InvalidSecret,
  InvalidSecretShare,
  InvalidPublicShare,
  InvalidInput,
} from 'vsslib/errors';
