import { Point, Group } from './backend/abstract';
import { Ciphertext } from './elgamal';
import { leInt2Buff } from './arith';
import { NizkProof } from './nizk';
import {
  SecretShare,
  PointShare,
  ShamirSharing,
  computeLambda,
  shareSecret,
  parseFeldmannPacket,
  parsePedersenPacket,
  reconstructSecret,
  reconstructPoint,
  verifyFeldmannCommitments,
  verifyPedersenCommitments,
  SharePacket,
} from './shamir';
import { PrivateKey, PublicKey } from './keys';
import { ErrorMessages } from './errors';
import { ElgamalSchemes, AesModes, Algorithms } from './enums';
import { ElgamalScheme, AesMode, Algorithm } from './types';

import elgamal from './elgamal';


export type PartialDecryptor = { value: Uint8Array, proof: NizkProof, index: number };


export class PrivateShare<P extends Point> extends PrivateKey<P> {
  index: number;

  constructor(ctx: Group<P>, secret: bigint, index: number) {
    super(ctx, leInt2Buff(secret));
    this.index = index;
  }

  _secretShare = () => new SecretShare(this.ctx, this.secret, this.index);

  static async fromFeldmannPacket(
    ctx: Group<Point>,
    commitments: Uint8Array[],
    packet: SharePacket
  ): Promise<PrivateShare<Point>> {
    const { value, index } = await parseFeldmannPacket(ctx, commitments, packet);
    return new PrivateShare(ctx, value, index);
  }

  static async fromPedersenPacket(
    ctx: Group<Point>,
    commitments: Uint8Array[],
    publicBytes: Uint8Array,
    packet: SharePacket,
  ): Promise<PrivateShare<Point>> {
    const { share: { value, index } } = await parsePedersenPacket(
      ctx,
      commitments,
      publicBytes,
      packet,
    );
    return new PrivateShare(ctx, value, index);
  }

  async getPublicShare(): Promise<PublicShare<P>> {
    return new PublicShare(
      this.ctx, await this.getPublicBytes(), this.index
    );
  }

  async computePartialDecryptor(
    ciphertext: Ciphertext,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array
    },
  ): Promise<PartialDecryptor> {
    const { decryptor, proof } = await this.computeDecryptor(
      ciphertext,
      opts,
    );
    return { value: decryptor, proof, index: this.index };
  }
};



export class PublicShare<P extends Point> extends PublicKey<P> {
  index: number;

  constructor(ctx: Group<P>, bytes: Uint8Array, index: number) {
    super(ctx, bytes);
    this.index = index;
  }

  asPointShare = async (): Promise<PointShare<P>> => {
    return {
      value: await this.asPoint(),
      index: this.index,
    }
  }

  async verifyPartialDecryptor<A>(
    ciphertext: Ciphertext,
    decryptor: PartialDecryptor,
    opts?: {
      nonce?: Uint8Array,
      raiseOnInvalid?: boolean
    },
  ): Promise<boolean> {
    const { ctx, index } = this;
    const { value, proof } = decryptor;
    const nonce = opts ? opts.nonce : undefined;
    const { alpha, beta } = ciphertext;
    const verified = await this.verifyDecryptor(
      ciphertext,
      value,
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


export class KeySharing<P extends Point> extends ShamirSharing<P> {
  getPrivateShares = async (): Promise<PrivateShare<P>[]> => {
    const shares = await this.getSecretShares();
    return shares.map(
      ({ index, value }) => new PrivateShare(this.ctx, value, index)
    );
  }

  getPublicShares = async (): Promise<PublicShare<P>[]> => {
    const shares = await this.getPointShares();
    return shares.map(
      ({ index, value }) => new PublicShare(this.ctx, value.toBytes(), index)
    );
  }

  generateFeldmannCommitments = async (): Promise<Uint8Array[]> => {
    const { commitments } = await this.proveFeldmann();
    return commitments;
  }

  generatePedersenCommitments = async (publicBytes: Uint8Array): Promise<{
    commitments: Uint8Array[],
    bindings: Uint8Array[],
  }> => {
    return this.provePedersen(publicBytes);
  }
}


export async function shareKey<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  privateKey: PrivateKey<P>
): Promise<KeySharing<P>> {
  const { polynomial } = await shareSecret(
    ctx, nrShares, threshold, privateKey.secret
  );
  return new KeySharing(ctx, nrShares, threshold, polynomial);
}

export async function reconstructKey<P extends Point>(
  ctx: Group<P>,
  shares: PrivateShare<P>[],
  threshold?: number
): Promise<PrivateKey<P>> {
  if (threshold && shares.length < threshold)
    throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
  const secret = await reconstructSecret(ctx, shares.map(s => s._secretShare()));
  return new PrivateKey(ctx, leInt2Buff(secret));
}

export async function reconstructPublic<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare<P>[],
  threshold?: number
): Promise<PublicKey<P>> {
  if (threshold && shares.length < threshold)
    throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
  const pointShares = new Array<PointShare<P>>(shares.length);
  for (let i = 0; i < pointShares.length; i++) {
    pointShares[i] = await shares[i].asPointShare();
  }
  const combined = await reconstructPoint(ctx, pointShares);
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
  const { order, neutral, exp, operate, unpackValid } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = neutral;
  for (const share of shares) {
    const { value, index } = share;
    const lambda = computeLambda(ctx, index, qualifiedIndexes);
    const curr = await exp(lambda, await unpackValid(value));
    acc = await operate(acc, curr);
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
