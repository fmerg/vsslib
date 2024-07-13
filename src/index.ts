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

export { generateKey, extractPartialKey } from 'vsslib/keys';

export { distributeSecret } from 'vsslib/dealer';

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
  combinePartialDecryptors,
  parseSchnorrPacket,
  recoverPublic,
  recoverPublicKey,
  recoverDecryptor,
  thresholdDecrypt
} from 'vsslib/combiner';

export {
  InvalidSecretShare,
  InvalidPublicShare,
  InvalidInput,
} from 'vsslib/errors';
