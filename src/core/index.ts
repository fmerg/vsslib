const aes = require('./aes');
const elgamal = require('./elgamal');
const shamir = require('./shamir');
const lagrange = require('./lagrange');
const schnorr = require('./schnorr');
const hash = require('./hash');
import { plain, kem, ies } from './elgamal';

export {
  aes,
  elgamal,
  ies,
  hash,
  kem,
  lagrange,
  plain,
  schnorr,
  shamir,
}
