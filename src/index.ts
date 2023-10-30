import { PrivateKey, PublicKey } from './key';

const backend = require('./backend');
const key = require('./key');
const elgamal = require('./elgamal');
const sigma = require('./sigma');
const lagrange = require('./lagrange');
const shamir = require('./shamir');
const utils = require('./utils');

export {
  PrivateKey,
  PublicKey,
  backend,
  key,
  elgamal,
  sigma,
  lagrange,
  shamir,
  utils,
}
