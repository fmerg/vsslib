import { Point, Group } from '../backend/abstract';
import { Algorithms, AesModes } from '../enums';
import { Algorithm, AesMode } from '../types';
import { Cipher, Ciphertext } from './common';

const crypto = require('node:crypto');
const aes = require('../aes');
const utils = require('../utils');

type A = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  mac: Uint8Array,
  tag?: Uint8Array,
  mode: AesMode,
  algorithm: Algorithm,
}

export class IesCiphertext<P extends Point> extends Ciphertext<A, P> {
}

export class IesCipher<P extends Point> extends Cipher<Uint8Array, A, P> {
  constructor(ctx: Group<P>, opts?: { mode?: AesMode, algorithm?: Algorithm }) {
    super(ctx, opts);
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{ alpha: A, decryptor: P }> => {
    const { ctx: { generator, randomScalar, operate}, mode, algorithm } = this;
    const decryptor = await operate(randomness, pub);
    const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA512 });
    const keyAes = key.slice(0, 32);
    const keyMac = key.slice(32, 64);
    const { ciphered, iv, tag } = aes.encrypt(keyAes, message, { mode });
    const mac = Uint8Array.from(crypto.createHmac(algorithm, keyMac).update(ciphered).digest());
    return { alpha: { ciphered, iv, mac, tag, mode, algorithm }, decryptor };
  }

  decapsulate = async (alpha: A, decryptor: P): Promise<Uint8Array> => {
    const { ciphered, iv, mac, tag, mode, algorithm } = alpha;
    const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA512 });
    const keyAes = key.slice(0, 32);
    const keyMac = key.slice(32, 64);
    const targetMac = Uint8Array.from(crypto.createHmac(algorithm, keyMac).update(ciphered).digest());
    let isMacValid = true;
    isMacValid &&= mac.length === targetMac.length;
    for (let i = 0; i < mac.length; i++) {
      isMacValid &&= mac[i] === targetMac[i];
    }
    if (!isMacValid) throw new Error('Invalid MAC');
    const plaintext = aes.decrypt(keyAes, ciphered, iv, { mode, tag });
    return plaintext;
  }
}

export default function<P extends Point>(ctx: Group<P>, opts?: { mode?: AesMode, algorithm?: Algorithm }) {
  return new IesCipher(ctx, opts);
}
