const aes = require('./aes');
const elgamal = require('./elgamal');
const shamir = require('./shamir');
const lagrange = require('./lagrange');
const schnorr = require('./schnorr');
import { plain, kem, ies } from './elgamal';

export {
  aes,
  elgamal,
  ies,
  kem,
  lagrange,
  plain,
  schnorr,
  shamir,
}
