import { PrivateKey, PublicKey } from './keys';
import { PrivateShare, PublicShare } from './sharing';
import { plain, kem, ies } from './crypto';
import signer from './crypto/signer';

import { generateKey, VssParty } from './core';

const { aes, elgamal, hash } = require('./crypto');
const backend = require('./backend');
const crypto = require('./crypto');
const keys = require('./keys');
const lagrange = require('./lagrange');
const schemes = require('./schemes');
const shamir = require('./shamir');
const sigma = require('./crypto/sigma');
const errors = require('./errors');

export {
  generateKey,
  VssParty,
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
  schemes,
  signer,
  shamir,
  sigma,
  errors,
}
