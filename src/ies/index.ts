import { Point, Group } from '../backend/abstract';
import { Algorithms, AesModes } from '../enums';
import { Algorithm, AesMode } from '../types';
import { Ciphertext } from '../common';

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


export async function encrypt<P extends Point>(
  ctx: Group<P>,
  message: Uint8Array,
  pub: P,
  opts?: { mode?: AesMode, algorithm?: Algorithm },
): Promise<{ ciphertext: IesCiphertext<P>, decryptor: P, randomness: bigint }> {
  const { generator, randomScalar, operate } = ctx;
  const randomness = await randomScalar();
  const beta = await operate(randomness, generator);
  const decryptor = await operate(randomness, pub);
  const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA512 });
  const keyAes = key.slice(0, 32);
  const keyMac = key.slice(32, 64);
  const mode = opts ? (opts.mode || AesModes.DEFAULT) : AesModes.DEFAULT;
  const { ciphered, iv, tag } = aes.encrypt(keyAes, message, { mode });
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const mac = Uint8Array.from(crypto.createHmac(algorithm, keyMac).update(ciphered).digest());
  const ciphertext = { alpha: { ciphered, iv, mac, tag, mode, algorithm }, beta };
  return { ciphertext, decryptor, randomness };
}


export async function decrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: IesCiphertext<P>,
  secret: bigint,
): Promise<Uint8Array> {
  const { alpha: { ciphered, iv, mac, tag, mode, algorithm }, beta } = ciphertext;
  const { validatePoint, operate } = ctx;
  const isBetaValid = await validatePoint(beta, { raiseOnInvalid: false });
  if (!isBetaValid) throw new Error('Could not decrypt: beta is not on group');
  const decryptor = await operate(secret, beta);
  const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA512 });
  const keySym = key.slice(0, 32);
  const keyMac = key.slice(32, 64);
  const targetMac = Uint8Array.from(crypto.createHmac(algorithm, keyMac).update(ciphered).digest());
  let isMacValid = true;
  isMacValid &&= mac.length === targetMac.length;
  for (let i = 0; i < mac.length; i++) {
    isMacValid &&= mac[i] === targetMac[i];
  }
  if (!isMacValid) throw new Error('Could not decrypt: Invalid MAC');
  let plaintext;
  try {
    plaintext = aes.decrypt(keySym, ciphered, iv, { mode, tag });
  } catch (err: any) {
    throw new Error('Could not decrypt: ' + err.message);
  }
  return plaintext;
}
