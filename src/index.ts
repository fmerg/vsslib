import { PrivateKey, PublicKey } from './keys';
import { PrivateShare, PublicShare } from './sharing';
import { plain, kem, ies } from './crypto';
import signer from './crypto/signer';

import {
  generateKey,
  distributeKey,
  reconstructKey,
  reconstructPublic,
  verifyPartialDecryptors,
  reconstructDecryptor,
  thresholdDecrypt
} from './core';

const { aes, elgamal, hash } = require('./crypto');
const backend = require('./backend');
const crypto = require('./crypto');
const keys = require('./keys');
const lagrange = require('./lagrange');
const enums = require('./enums');
const types = require('./types');
const shamir = require('./shamir');
const nizk = require('./nizk');
const errors = require('./errors');
const serializers = require('./serializers');

export {
  generateKey,
  distributeKey,
  reconstructKey,
  reconstructPublic,
  reconstructDecryptor,
  verifyPartialDecryptors,
  thresholdDecrypt,
  PrivateKey,
  PublicKey,
  PrivateShare,
  PublicShare,
  aes,
  backend,
  plain,
  crypto,
  hash,
  ies,
  kem,
  keys,
  lagrange,
  enums,
  types,
  signer,
  shamir,
  nizk,
  errors,
  serializers,
}
