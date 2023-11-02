import { Algorithm } from '../types';
import { Point, Group } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { DlogProof } from '../sigma';
import { SecretShare, PublicShare } from './sharing';
import { Share, computeLambda, selectShare } from './common';
import { Messages } from './enums';

const elgamal = require('../elgamal');
const sigma = require('../sigma');


export class PartialDecryptor<P extends Point> implements Share<P> {
  value: P;
  index: number;
  proof: DlogProof<P>;

  constructor(value: P, index: number, proof: DlogProof<P>) {
    this.value = value;
    this.index = index;
    this.proof = proof;
  }
};


export async function generatePartialDecryptor<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>,
  share: SecretShare<P>,
  opts?: { algorithm?: Algorithm },
): Promise<PartialDecryptor<P>> {
  const { operate } = ctx;
  const { value, index } = share;
  const decryptor = await elgamal.generateDecryptor(ctx, value, ciphertext);
  const proof = await elgamal.proveDecryptor(ctx, ciphertext, value, decryptor, opts);
  return { value: decryptor, index, proof}
}


export async function verifyPartialDecryptor<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>,
  publicShare: PublicShare<P>,
  share: PartialDecryptor<P>,
): Promise<boolean> {
  const { value: pub } = publicShare;
  const { value, proof } = share;
  const verified = await elgamal.verifyDecryptor(ctx, ciphertext, pub, value, proof);
  if (!verified) throw new Error(Messages.INVALID_DECRYPTOR_SHARE);
  return true;
}


export async function verifyPartialDecryptors<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>,
  publicShares: PublicShare<P>[],
  shares: PartialDecryptor<P>[],
): Promise<[boolean, number[]]> {
  let flag = true;
  let indexes = [];
  for (const share of shares) {
    const { value, index, proof } = share;
    const { value: pub } = selectShare(index, publicShares);
    const verified = await elgamal.verifyDecryptor(ctx, ciphertext, pub, value, proof);
    flag &&= verified;
    if (!verified) indexes.push(index);
  }
  return [flag, indexes];
}


export async function reconstructDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor<P>[],
): Promise<P> {
  const { order, neutral, operate, combine } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = neutral;
  for (const share of shares) {
    const { value, index } = share;
    const lambda = computeLambda(index, qualifiedIndexes, order);
    const curr = await operate(lambda, value);
    acc = await combine(acc, curr);
  }
  return acc;
}


export async function decrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext<P>,
  shares: PartialDecryptor<P>[],
  opts?: { threshold?: number, publicShares?: PublicShare<P>[] },
): Promise<P> {
  const threshold = opts ? opts.threshold : undefined;
  const publicShares = opts ? opts.publicShares : undefined;
  if (threshold && shares.length < threshold) throw new Error(Messages.NOT_ENOUGH_SHARES);
  if (publicShares) {
    const [verified, indexes] = await verifyPartialDecryptors(
      ctx, ciphertext, publicShares, shares
    );
    if (!verified) throw new Error(Messages.INVALID_DECRYPTOR_SHARES_DETECTED);
  }
  const decryptor = await reconstructDecryptor(ctx, shares);
  return elgamal.decrypt(ctx, ciphertext, { decryptor });
}
