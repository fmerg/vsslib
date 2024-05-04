import { Point, Group } from './backend/abstract';
import { Ciphertext } from './crypto/elgamal';
import { leInt2Buff } from './crypto/bitwise';
import { NizkProof } from './nizk';
import { BaseShare, BaseSharing } from './base';
import { SecretShare } from './shamir';
import { PrivateKey, PublicKey } from './keys';
import { ErrorMessages } from './errors';
import { ElgamalSchemes, AesModes, Algorithms } from './enums';
import { ElgamalScheme, AesMode, Algorithm } from './types';

import elgamal from './crypto/elgamal';
const shamir = require('./shamir');


export class PrivateShare<P extends Point> extends PrivateKey<P> implements BaseShare<bigint>{
  value: bigint;
  index: number;

  constructor(ctx: Group<P>, secret: bigint, index: number) {
    super(ctx, leInt2Buff(secret));
    this.value = this.secret;
    this.index = index;
  }

  async publicShare(): Promise<PublicShare<P>> {
    const { ctx } = this;
    const pubPoint = await ctx.operate(this.secret, ctx.generator);
    return new PublicShare(ctx, pubPoint.toBytes(), this.index);
  }

  async generatePartialDecryptor(
    ciphertext: Ciphertext,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array
    },
  ): Promise<PartialDecryptor<P>> {
    const { alpha, beta } = ciphertext;
    const { decryptor, proof } = await this.generateDecryptor(
      ciphertext,
      opts,
    );
    return { value: decryptor, index: this.index, proof };
  }
};


export class PublicShare<P extends Point> extends PublicKey<P> {
  value: P;
  index: number;

  constructor(ctx: Group<P>, bytes: Uint8Array, index: number) {
    super(ctx, bytes);
    this.value = this.ctx.unpack(this.bytes);
    this.index = index;
  }

  async verifyPartialDecryptor<A>(
    ciphertext: Ciphertext,
    partialDecryptor: PartialDecryptor<P>,
    opts?: { nonce?: Uint8Array, raiseOnInvalid?: boolean },
  ): Promise<boolean> {
    const { ctx, index } = this;
    const { value: decryptor, proof } = partialDecryptor;
    const nonce = opts ? opts.nonce : undefined;
    const { alpha, beta } = ciphertext;
    const verified = await this.verifyDecryptor(
      ciphertext,
      decryptor,
      proof,
      {
        nonce,
        raiseOnInvalid: false
      }
    );
    const raiseOnInvalid = opts ?
      (opts.raiseOnInvalid === undefined ? true : opts.raiseOnInvalid) :
      true;
    if (!verified && raiseOnInvalid) throw new Error(
      ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
    return verified;
  }
};

export class KeySharing<P extends Point> extends BaseSharing<
  bigint, P, PrivateShare<P>, PublicShare<P>
> {
  getSecretShares = async (): Promise<PrivateShare<P>[]> => {
    const { ctx, polynomial, nrShares } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const value = polynomial.evaluate(index);
      shares.push(new PrivateShare(ctx, value, index));
    }
    return shares;
  }

  getPublicShares = async (): Promise<PublicShare<P>[]> => {
    const { nrShares, polynomial: { evaluate }, ctx: { operate, generator } } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const pubPoint = await operate(evaluate(index), generator);
      const newShare = new PublicShare(this.ctx, pubPoint.toBytes(), index);
      shares.push(newShare);
    }
    return shares;
  }
}


export class PartialDecryptor<P extends Point>{
  value: Uint8Array;
  index: number;
  proof: NizkProof<P>;

  constructor(value: Uint8Array, index: number, proof: NizkProof<P>) {
    this.value = value;
    this.index = index;
    this.proof = proof;
  }
};


export async function distributeKey<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  privateKey: PrivateKey<P>
): Promise<KeySharing<P>> {
  const { polynomial } = await shamir.shareSecret(
    ctx, nrShares, threshold, privateKey.secret
  );
  return new KeySharing(ctx, nrShares, threshold, polynomial);
}

export async function verifyFeldmann<P extends Point>(
  ctx: Group<P>,
  share: PrivateShare<P>,
  commitments: P[]
): Promise<boolean> {
  const secretShare = new SecretShare(share.value, share.index);
  const verified = await shamir.verifyFeldmann(
    ctx, secretShare, commitments
  );
  if (!verified) throw new Error(ErrorMessages.INVALID_SHARE);
  return verified;
}

export async function verifyPedersen<P extends Point>(
  ctx: Group<P>,
  share: PrivateShare<P>,
  binding: bigint,
  pub: P,
  commitments: P[]
): Promise<boolean> {
  const secretShare = new SecretShare(share.value, share.index);
  const verified = await shamir.verifyPedersen(
    ctx, secretShare, binding, pub, commitments
  );
  if (!verified) throw new Error(ErrorMessages.INVALID_SHARE);
  return verified;
}

export async function reconstructKey<P extends Point>(
  ctx: Group<P>,
  shares: PrivateShare<P>[],
  threshold?: number
): Promise<PrivateKey<P>> {
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const secretShares = shares.map(({ secret: value, index }) => { return { value, index } });
  const secret = await shamir.reconstructSecret(ctx, secretShares);
  return new PrivateKey(ctx, leInt2Buff(secret));
}

export async function reconstructPublic<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare<P>[],
  threshold?: number
): Promise<PublicKey<P>> {
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const pubShares = shares.map(({ value, index }) => { return { value, index } });
  const combined = await shamir.reconstructPublic(ctx, pubShares);
  return new PublicKey(ctx, combined.toBytes());
}

// TODO: Include indexed nonces option?
export async function verifyPartialDecryptors<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  publicShares: PublicShare<P>[],
  shares: PartialDecryptor<P>[],
  opts?: { threshold?: number, raiseOnInvalid?: boolean },
): Promise<{ flag: boolean, indexes: number[]}> {
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const selectPublicShare = (index: number, shares: PublicShare<P>[]) => {
    const selected = shares.filter(share => share.index == index)[0];
    if (!selected) throw new Error('No share with index');
    return selected;
  }
  let flag = true;
  let indexes = [];
  const raiseOnInvalid = opts ? (opts.raiseOnInvalid || false) : false;
  for (const partialDecryptor of shares) {
    const publicShare = selectPublicShare(partialDecryptor.index, publicShares);
    const verified = await publicShare.verifyPartialDecryptor(
      ciphertext,
      partialDecryptor,
      {
        raiseOnInvalid: false,
      }
    );
    if (!verified && raiseOnInvalid)
      throw new Error(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
    flag &&= verified;
    if(!verified) indexes.push(partialDecryptor.index);
  }
  return { flag, indexes };
}

export async function reconstructDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor<P>[],
  opts?: { threshold?: number, publicShares?: PublicShare<P>[] }
): Promise<Uint8Array> {
  // TODO: Include validation
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const { order, neutral, operate, combine, unpack } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = neutral;
  for (const share of shares) {
    const { value, index } = share;
    const lambda = shamir.computeLambda(ctx, index, qualifiedIndexes);
    const curr = await operate(lambda, unpack(value));
    acc = await combine(acc, curr);
  }
  return acc.toBytes();
}


export async function thresholdDecrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  shares: PartialDecryptor<P>[],
  opts: {
    scheme: ElgamalScheme,
    mode?: AesMode,
    algorithm?: Algorithm,
    threshold?: number,
  },
): Promise<Uint8Array> {
  let { scheme, mode, algorithm, threshold } = opts;
  // TODO: Include public schares option for validation?
  const decryptor = await reconstructDecryptor(ctx, shares, { threshold });
  algorithm = algorithm || Algorithms.DEFAULT;
  mode = mode || AesModes.DEFAULT;
  return elgamal(ctx, scheme, algorithm, mode).decryptWithDecryptor(
    ciphertext,
    decryptor,
  );
}
