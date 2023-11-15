import { Point, Group } from '../backend/abstract';
import { Algorithms, AesModes } from '../enums';
import { Algorithm, AesMode } from '../types';

const crypto = require('node:crypto');

const aes = require('../aes');
const utils = require('../utils');


export type IesCiphertext<P extends Point> = {
  ciphered: Uint8Array,
  beta: P,
  iv: Uint8Array,
  mode: AesMode,
  algorithm: Algorithm,
  mac: Uint8Array,
  tag?: Uint8Array,
}


export async function encrypt<P extends Point>(
  ctx: Group<P>,
  message: Uint8Array,
  pub: P,
  opts?: { mode?: AesMode, algorithm?: Algorithm },
): Promise<{ ciphertext: IesCiphertext<P>, decryptor: P, randomness: bigint }> {
  const mode = opts ? (opts.mode || AesModes.DEFAULT) : AesModes.DEFAULT;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const { generator, randomScalar, operate } = ctx;
  const randomness = await randomScalar();
  const beta = await operate(randomness, generator);
  const decryptor = await operate(randomness, pub);
  const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA512 });
  const keySym = key.slice(0, 32);
  const keyMac = key.slice(32, 64);
  const { ciphered, iv, tag } = aes.encrypt(keySym, message, { mode });
  const mac = Uint8Array.from(crypto.createHmac(algorithm, keyMac).update(ciphered).digest());
  const ciphertext = {
    ciphered,
    beta,
    iv,
    mode,
    algorithm,
    tag,
    mac,
  };
  return { ciphertext, decryptor, randomness };
}


export async function decrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: IesCiphertext<P>,
  secret: bigint,
): Promise<Uint8Array> {
  const { ciphered, beta, iv, mode, algorithm, tag, mac } = ciphertext;
  const { validatePoint, operate } = ctx;
  let validPoint;
  try {
    validPoint = await validatePoint(beta);
  } catch (err: any) {
    throw new Error('Could not decrypt: ' + err.message);
  } finally {
    // TODO: Guarantee that validatePoint raises and remove this check
    if (!validPoint) throw new Error('Could not decrypt: Point not in subgroup');
  }
  const decryptor = await operate(secret, beta);
  const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA512 });
  const keySym = key.slice(0, 32);
  const keyMac = key.slice(32, 64);
  const _mac = Uint8Array.from(crypto.createHmac(algorithm, keyMac).update(ciphered).digest());
  let areMacEqual = true;
  areMacEqual &&= mac.length === _mac.length;
  for (let i = 0; i < mac.length; i++) {
    areMacEqual &&= mac[i] === _mac[i];
  }
  if (!areMacEqual) throw new Error('Could not decrypt: Invalid MAC');
  let deciphered;
  try {
    deciphered = aes.decrypt(keySym, ciphered, iv, { mode, tag });
  } catch (err: any) {
    throw new Error('Could not decrypt: ' + err.message);
  }
  return deciphered;
}
