import { Point, Group } from '../backend/abstract';
import { Algorithms, AesModes } from '../enums';
import { Algorithm, AesMode } from '../types';
import { Ciphertext } from '../common';

const aes = require('../aes');
const utils = require('../utils');


type A = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  tag?: Uint8Array,
  mode: AesMode,
};

export class KemCiphertext<P extends Point> extends Ciphertext<A, P> {
}


export async function encrypt<P extends Point>(
  ctx: Group<P>,
  message: Uint8Array,
  pub: P,
  opts?: { mode?: AesMode }
): Promise<{ ciphertext: KemCiphertext<P>, decryptor: P, randomness: bigint }> {
  const { generator, randomScalar, operate } = ctx;
  const randomness = await randomScalar();
  const beta = await operate(randomness, generator);
  const decryptor = await operate(randomness, pub);
  const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA256 });
  const { ciphered, iv, tag } = aes.encrypt(key, message, opts);
  const mode = opts ? (opts.mode || AesModes.DEFAULT) : AesModes.DEFAULT;
  const ciphertext = { alpha: { ciphered, iv, tag, mode }, beta };
  return { ciphertext, decryptor, randomness };
}


export async function decrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: KemCiphertext<P>,
  secret: bigint,
): Promise<Uint8Array> {
  const { alpha: { ciphered, iv, tag, mode }, beta } = ciphertext;
  const decryptor = await ctx.operate(secret, beta);
  const key = await utils.hash(decryptor.toBytes(), { algorithm: Algorithms.SHA256 });
  let plaintext;
  try {
    plaintext = aes.decrypt(key, ciphered, iv, { mode, tag });
  } catch (err: any) {
    throw new Error('Could not decrypt: ' + err.message);
  }
  return plaintext;
}
