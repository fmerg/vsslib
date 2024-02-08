import { PrivateKey, PublicKey, PrivateShare, PublicShare } from './key';
import { plain, kem, ies } from './elgamal';
import schnorr from './schnorr';

const aes = require('./aes');
const backend = require('./backend');
const tds = require('./tds');
const key = require('./key');
const polynomials = require('./polynomials');
const shamir = require('./shamir');
const sigma = require('./sigma');
const utils = require('./utils');

export {
  PrivateKey,
  PublicKey,
  PrivateShare,
  PublicShare,
  aes,
  backend,
  tds,
  plain,
  ies,
  kem,
  key,
  polynomials,
  schnorr,
  shamir,
  sigma,
  utils,
}
