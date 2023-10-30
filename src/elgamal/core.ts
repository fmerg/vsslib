import { Label } from '../types';
import { Algorithms } from '../enums';
import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { DlogProof, DDHTuple } from '../sigma';

const utils = require('../utils');
const sigma = require('../sigma');


export type Ciphertext<P extends Point>= {
  alpha: P,
  beta: P
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
): Promise<{ ciphertext: Ciphertext<P>, randomness: bigint, decryptor: P }> {
  const { generator, randomScalar, operate, combine } = ctx;
  const randomness = await randomScalar();
  const decryptor = await operate(randomness, pub);
  const alpha = await combine(decryptor, message);
  const beta = await operate(randomness, generator);
  return { ciphertext: { alpha, beta }, randomness, decryptor };
}

export async function decrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>, 
  opts: DecryptionOptions<P>
): Promise<P> {
  const { operate, invert, combine } = ctx;
  const { alpha, beta } = ciphertext;
  let { secret, decryptor, randomness, pub } = opts;
  decryptor = decryptor || (
    secret ? await operate(secret, beta) : await operate(randomness!, pub!)
  )
  const dInv = await invert(decryptor);
  return combine(alpha, dInv);
}

export async function proveEncryption<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>,
  randomness: bigint, 
  opts?: { algorithm?: Algorithm }
): Promise<DlogProof<P>> {
  return sigma.proveDlog(ctx, randomness, ctx.generator,  ciphertext.beta, opts);
}

export async function verifyEncryption<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>,
  proof: DlogProof<P>
): Promise<boolean> {
  return sigma.verifyDlog(ctx, ctx.generator, ciphertext.beta, proof);
}

export async function proveDecryptor<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>,
  secret: bigint,
  decryptor: P,
  opts?: { algorithm?: Algorithm }
): Promise<DlogProof<P>> {
  const pub = await ctx.operate(secret, ctx.generator);
  return sigma.proveDDH(ctx, secret, { u: ciphertext.beta, v: pub, w: decryptor }, opts);
}

export async function verifyDecryptor<P extends Point>(
  ctx: Group<P>,
  decryptor: P,
  ciphertext: Ciphertext<P>,
  pub: P,
  proof: DlogProof<P>
): Promise<boolean> {
  return sigma.verifyDDH(ctx, { u: ciphertext.beta, v: pub, w: decryptor }, proof);
}
