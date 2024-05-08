import { Point, Group } from './backend/abstract';
import { Ciphertext } from './elgamal';
import { leInt2Buff } from './crypto/bitwise';
import { NizkProof } from './nizk';
import { SecretShare, PubShare, BaseSharing } from './base';
import { ScalarShare, ShamirSharing } from './shamir';
import { PrivateKey, PublicKey } from './keys';
import { ErrorMessages } from './errors';
import { ElgamalSchemes, AesModes, Algorithms } from './enums';
import { ElgamalScheme, AesMode, Algorithm } from './types';
import { randomPolynomial } from './lagrange';

import elgamal from './elgamal';
const shamir = require('./shamir');


export class PrivateShare<P extends Point> extends PrivateKey<P> implements SecretShare<
  P, bigint, Uint8Array, bigint
>{
  _share: ScalarShare<P>;
  value: bigint;
  index: number;

  constructor(ctx: Group<P>, secret: bigint, index: number) {
    super(ctx, leInt2Buff(secret));
    this.value = this.secret;
    this.index = index;
    this._share = new ScalarShare(ctx, this.value, this.index);
  }

  toInner = async (commitments: Uint8Array[]) => {
    const innerCommitments = new Array(commitments.length);
    const ctx = this.ctx;
    for (const [i, cBytes] of commitments.entries()) {
      const cPoint = ctx.unpack(cBytes);
      await ctx.validatePoint(cPoint);
      innerCommitments[i] = cPoint
    }
    return innerCommitments;
  }

  verifyFeldmann = async (commitments: Uint8Array[]): Promise<boolean> => {
    const verified = await this._share.verifyFeldmann(await this.toInner(commitments));
    if (!verified) throw new Error(ErrorMessages.INVALID_SHARE);
    return verified;
  }

  verifyPedersen = async (
    binding: bigint, commitments: Uint8Array[], publicBytes: Uint8Array
  ): Promise<boolean> => {
    const pub = this.ctx.unpack(publicBytes);
    await this.ctx.validatePoint(pub);
    const verified = await this._share.verifyPedersen(
      binding, await this.toInner(commitments), pub
    );
    if (!verified) throw new Error(ErrorMessages.INVALID_SHARE);
    return verified;
  }

  async publicShare(): Promise<PublicShare<P>> {
    const ctx = this.ctx;
    const pubPoint = await ctx.operate(this.secret, ctx.generator);
    return new PublicShare(ctx, pubPoint.toBytes(), this.index);
  }

  async generatePartialDecryptor(
    ciphertext: Ciphertext,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array
    },
  ): Promise<PartialDecryptor> {
    const { decryptor: value, proof } = await this.generateDecryptor(
      ciphertext,
      opts,
    );
    return { value, proof, index: this.index };
  }
};


export class PublicShare<P extends Point> extends PublicKey<P> implements PubShare<
  P, P
> {
  value: P;
  index: number;

  constructor(ctx: Group<P>, bytes: Uint8Array, index: number) {
    super(ctx, bytes);
    this.value = this.ctx.unpack(this.bytes);
    this.index = index;
  }

  async verifyPartialDecryptor<A>(
    ciphertext: Ciphertext,
    partialDecryptor: PartialDecryptor,
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
  P, Uint8Array, bigint, PrivateShare<P>,  PublicShare<P>
>{
  _sharing: ShamirSharing<P>;

  constructor(sharing: ShamirSharing<P>) {
    const { ctx, threshold, nrShares, polynomial } = sharing;
    super(ctx, nrShares, threshold, polynomial);
    this._sharing = sharing;
  }

  getSecretShares = async (): Promise<PrivateShare<P>[]> => {
    const secretShares = await this._sharing.getSecretShares();
    return secretShares.map(
      ({ index, value }) => new PrivateShare(this.ctx, value, index)
    );
  }

  getPublicShares = async (): Promise<PublicShare<P>[]> => {
    const publicShares = await this._sharing.getPublicShares();
    return publicShares.map(
      ({ index, value }) => new PublicShare(this.ctx, value.toBytes(), index)
    );
  }

  proveFeldmann = async (): Promise<{ commitments: Uint8Array[] }> => {
    const { commitments } = await this._sharing.proveFeldmann();
    return {
      commitments: commitments.map(c => c.toBytes())
    }
  }

  provePedersen = async (publicBytes: Uint8Array): Promise<{
    commitments: Uint8Array[],
    bindings: bigint[],
  }> => {
    const pub = this.ctx.unpack(publicBytes)
    await this.ctx.validatePoint(pub);
    const { commitments, bindings } = await this._sharing.provePedersen(pub);
    return {
      commitments: commitments.map(c => c.toBytes()),
      bindings,
    }
  }
}


export class PartialDecryptor{
  value: Uint8Array;
  proof: NizkProof;
  index: number;

  constructor(value: Uint8Array, index: number, proof: NizkProof) {
    this.value = value;
    this.proof = proof;
    this.index = index;
  }
};


export async function distributeKey<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  privateKey: PrivateKey<P>
): Promise<KeySharing<P>> {
  const { secret } = privateKey;
  const sharing = await shamir.shareSecret(
    ctx, nrShares, threshold, secret
  );
  return new KeySharing(sharing);
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
  shares: PartialDecryptor[],
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
  shares: PartialDecryptor[],
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
  shares: PartialDecryptor[],
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
