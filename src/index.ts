export { initBackend } from 'vsslib/backend';

export {
  Systems,
  Algorithms,
  BlockModes,
  ElgamalSchemes,
  SignatureSchemes,
} from 'vsslib/enums';

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

export { generateKey } from 'vsslib/keys';

export { shareSecret, shareKey } from 'vsslib/dealer';

export {
  extractPublicShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
  parsePartialKey,
  PartialKey,
  PartialPublicKey,
  PartialDecryptor
} from 'vsslib/shareholder';

export {
  computeLambda,
  combineSecretShares,
  combinePublicShares,
  combinePartialDecryptors,
  parseSchnorrPacket,
  recoverPublic,
  recoverPublicKey,
  recoverDecryptor,
  thresholdDecrypt
} from 'vsslib/combiner';

export {
  ElgamalError,
  InvalidSecret,
  InvalidSecretShare,
  InvalidPublicShare,
  InvalidDecryptor,
  InvalidInput,
} from 'vsslib/errors';
