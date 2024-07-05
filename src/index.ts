import { initBackend } from './backend';
import { generateKey, extractPartialKey } from './keys';
import {
  combineSecretShares,
  combinePublicShares,
  recoverPublic,
  recoverPublicKey,
  combinePartialDecryptors,
  recoverDecryptor,
  thresholdDecrypt
} from './combiner';

import {
  distributeSecret,
  extractPublicShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicPacket,
  parsePublicPacket,
} from './dealer';

import {
  generateSecret,
  extractPublic,
  isEqualSecret,
  isEqualPublic,
  isKeypair,
} from './secrets';


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
  generateSecret,
  isEqualSecret,
  isEqualPublic,
  extractPublic,
  isKeypair,
  generateKey,
  extractPartialKey,
  distributeSecret,
  extractPublicShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicPacket,
  parsePublicPacket,
  combineSecretShares,
  combinePublicShares,
  recoverPublic,
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
