import { initBackend } from './backend';
import { generateKey } from './keys';
import {
  combinePublicShares,
  recoverPublicKey,
  combinePartialDecryptors,
  recoverDecryptor,
  thresholdDecrypt
} from './combiner';

import {
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicSharePacket,
  parsePublicSharePacket,
} from './dealer';


const backend = require('./backend');
const crypto = require('./crypto');
const elgamal = require('./elgamal');
const enums = require('./enums');
const keys = require('./keys');
const lagrange = require('./lagrange');
const nizk = require('./nizk');
const dealer = require('./dealer');
const signer = require('./signer');


export {
  initBackend,
  generateKey,
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicSharePacket,
  parsePublicSharePacket,
  combinePublicShares,
  recoverPublicKey,
  combinePartialDecryptors,
  recoverDecryptor,
  thresholdDecrypt,
  backend,
  crypto,
  elgamal,
  enums,
  keys,
  lagrange,
  nizk,
  dealer,
  signer,
}
