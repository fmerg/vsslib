import { Point, Group } from '../backend/abstract';
import { Algorithms, AesModes } from '../enums';
import { Algorithm, AesMode } from '../types';

const aes = require('../aes');
const utils = require('../utils');


export type KemCiphertext<P extends Point> = {
  ciphered: Uint8Array,
  beta: P,
  iv: Uint8Array,
  mode: AesMode,
  tag?: Uint8Array,
}


export async function encrypt<P extends Point>(
  ctx: Group<P>,
  message: Uint8Array,
  pub: P,
  opts?: { mode?: AesMode }
): Promise<{ ciphertext: KemCiphertext<P>, decryptor: P, randomness: bigint }> {
  const mode = opts ? (opts.mode || AesModes.DEFAULT) : AesModes.DEFAULT;
  const { generator, randomScalar, operate } = ctx;
  const randomness = await randomScalar();
  const beta = await operate(randomness, generator);
  const decryptor = await operate(randomness, pub);
  const encapsKey = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA256 });
  const { ciphered, iv, tag } = aes.encrypt(encapsKey, message, opts);
  const ciphertext = { ciphered, beta, iv, mode, tag };
  return { ciphertext, decryptor, randomness };
}


export async function decrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: KemCiphertext<P>,
  secret: bigint,
): Promise<Uint8Array> {
  const { ciphered, beta, iv, mode, tag } = ciphertext;
  const decryptor = await ctx.operate(secret, beta);
  const encapsKey = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA256 });
  let deciphered;
  try {
    deciphered = aes.decrypt(encapsKey, ciphered, iv, { mode, tag });
  } catch (err: any) {
    throw new Error('Could not decrypt: ' + err.message);
  }
  return deciphered;
}
