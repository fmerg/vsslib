import { Label, Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Group, Point } from '../backend/abstract';
import { SigmaProof } from '../sigma';
import { Ciphertext } from '../common';

const utils = require('../utils');
const sigma = require('../sigma');

export class ElGamalCiphertext<P extends Point> extends Ciphertext<P, P> {
}


export type DecryptionOptions<P>= {
  secret: bigint,
  decryptor?: never,
  randomness?: never,
  pub?: never,
} | {
  secret?: never,
  decryptor: P,
  randomness?: never,
  pub?: never,
} | {
  secret?: never,
  decryptor?: never,
  randomness: bigint,
  pub: P,
}


export async function encrypt<P extends Point>(
  ctx: Group<P>,
  message: P,
  pub: P
): Promise<{ ciphertext: ElGamalCiphertext<P>, randomness: bigint, decryptor: P }> {
  const { generator, randomScalar, operate, combine } = ctx;
  const randomness = await randomScalar();
  const decryptor = await operate(randomness, pub);
  const alpha = await combine(decryptor, message);
  const beta = await operate(randomness, generator);
  const ciphertext = { alpha, beta };
  return { ciphertext, randomness, decryptor };
}

export async function decrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: ElGamalCiphertext<P>,
  opts: DecryptionOptions<P>
): Promise<P> {
  const { alpha, beta } = ciphertext;
  const { operate, invert, combine } = ctx;
  let { secret, decryptor, randomness, pub } = opts;
  decryptor = decryptor || (
    secret ? await operate(secret, beta) : await operate(randomness!, pub!)
  )
  const dInv = await invert(decryptor);
  const plaintext = await combine(alpha, dInv);
  return plaintext;
}
