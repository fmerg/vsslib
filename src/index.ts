import { PrivateKey, PublicKey, PrivateShare, PublicShare } from './key';

const backend = require('./backend');
const core = require('./core');
const elgamal = require('./elgamal');
const key = require('./key');
const lagrange = require('./lagrange');
const shamir = require('./shamir');
const sigma = require('./sigma');
const utils = require('./utils');

export {
  PrivateKey,
  PublicKey,
  PrivateShare,
  PublicShare,
  backend,
  core,
  elgamal,
  key,
  lagrange,
  shamir,
  sigma,
  utils,
}
