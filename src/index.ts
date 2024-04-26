import { PrivateKey, PublicKey, PrivateShare, PublicShare } from './key';
import { plain, kem, ies } from './core';
import signer from './core/signer';

const { aes, elgamal, hash } = require('./core');
const backend = require('./backend');
const core = require('./core');
const tds = require('./tds');
const key = require('./key');
const lagrange = require('./lagrange');
const schemes = require('./schemes');
const shamir = require('./shamir');
const sigma = require('./core/sigma');

export {
  PrivateKey,
  PublicKey,
  PrivateShare,
  PublicShare,
  aes,
  backend,
  tds,
  plain,
  core,
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
