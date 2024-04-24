import { PrivateKey, PublicKey, PrivateShare, PublicShare } from './key';
import { plain, kem, ies } from './crypto';
import signer from './crypto/signer';

import { VssParty } from './core';

const { aes, elgamal, hash } = require('./crypto');
const backend = require('./backend');
const crypto = require('./crypto');
const key = require('./key');
const lagrange = require('./lagrange');
const schemes = require('./schemes');
const shamir = require('./shamir');
const sigma = require('./crypto/sigma');

export {
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
  key,
  lagrange,
  schemes,
  signer,
  shamir,
  sigma,
}
