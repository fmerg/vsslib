import { PrivateKey, PublicKey, PrivateShare, PublicShare } from './key';
import { plain, kem, ies } from './elgamal';
import schnorr from './schnorr';

const aes = require('./aes');
const backend = require('./backend');
const tds = require('./tds');
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
  aes,
  backend,
  tds,
  plain,
  ies,
  kem,
  key,
  lagrange,
  schnorr,
  shamir,
  sigma,
  utils,
}
