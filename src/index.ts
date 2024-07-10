export { initBackend } from 'vsslib/backend';

export {
  Systems,
  Algorithms,
  BlockModes,
  ElgamalSchemes,
  SignatureSchemes,
} from 'vsslib/enums';

export {
  generateSecret,
  extractPublic,
  isEqualSecret,
  isEqualPublic,
  isKeypair,
  addSecrets,
  combinePublics,
} from 'vsslib/secrets';

export {
  generateKey,
  extractPartialKey,
} from 'vsslib/keys';

export {
  distributeSecret,
  extractPublicShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createScnorrPacket,
  parseScnorrPacket,
} from 'vsslib/dealer';

export {
  combineSecretShares,
  combinePublicShares,
  recoverPublic,
  recoverPublicKey,
  combinePartialDecryptors,
  recoverDecryptor,
  thresholdDecrypt
} from 'vsslib/combiner';
