import { Label, Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Group, Point } from '../backend/abstract';
import { SigmaProof } from '../sigma';
import { Ciphertext } from '../common';

const utils = require('../utils');
const sigma = require('../sigma');

export class ElGamalCiphertext<P extends Point> extends Ciphertext<P, P> {
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
  secret: bigint,
): Promise<P> {
  const { alpha, beta } = ciphertext;
  const { operate, invert, combine } = ctx;
  const decryptor = await operate(secret, beta);
  const dInv = await invert(decryptor);
  const plaintext = await combine(alpha, dInv);
  return plaintext;
}

export async function decryptWithDecryptor<P extends Point>(
  ctx: Group<P>,
  ciphertext: ElGamalCiphertext<P>,
  decryptor: P,
): Promise<P> {
  const decryptorInverse = await ctx.invert(decryptor);
  const plaintext = await ctx.combine(ciphertext.alpha, decryptorInverse);
  return plaintext;
}

export async function decryptWithRandomness<P extends Point>(
  ctx: Group<P>,
  ciphertext: ElGamalCiphertext<P>,
  pub: P,
  randomness: bigint,
): Promise<P> {
  const decryptor = await ctx.operate(randomness, pub);
  const decryptorInverse = await ctx.invert(decryptor);
  const plaintext = await ctx.combine(ciphertext.alpha, decryptorInverse);
  return plaintext;
}
