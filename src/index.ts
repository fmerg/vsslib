import { initBackend } from './backend';
import { generateKey, extractPartialKey } from './keys';
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
  createPublicPacket,
  parsePublicPacket,
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
  extractPartialKey,
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicPacket,
  parsePublicPacket,
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
