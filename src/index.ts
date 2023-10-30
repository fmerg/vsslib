import { Key, Public } from './key';

const backend = require('./backend');
const elgamal = require('./elgamal');
const sigma = require('./sigma');
const lagrange = require('./lagrange');
const shamir = require('./shamir');
const utils = require('./utils');

export {
  Key,
  Public,
  backend,
  elgamal,
  sigma,
  lagrange,
  shamir,
  utils,
}
