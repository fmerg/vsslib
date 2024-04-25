import { Point, Group } from './backend/abstract';
import { leInt2Buff } from './crypto/bitwise';
import { ElgamalCiphertext } from './crypto/elgamal';
import { NizkProof } from './nizk';
import { BaseShare } from './base';
import { PrivateKey, PublicKey } from './keys';
import { ErrorMessages } from './errors';
import { PrivateShare, PublicShare, PartialDecryptor, KeySharing } from './sharing';
import {
  ElgamalScheme, ElgamalSchemes,
  AesMode, AesModes,
  Algorithm, Algorithms,
  Label,
} from './schemes';

import shamir from './shamir';
const elgamal = require('./crypto/elgamal');
const backend = require('./backend');


type KeyPair<P extends Point> = { privateKey: PrivateKey<P>, publicKey: PublicKey<P>, ctx: Group<P> };

export async function generateKey(label: Label): Promise<KeyPair<Point>> {
  const ctx = backend.initGroup(label);
  const privateKey = new PrivateKey(ctx, await ctx.randomBytes());
  const publicKey = await privateKey.publicKey();
  return { privateKey, publicKey, ctx };
}


export class VssParty<P extends Point> {
  ctx: Group<P>;

  constructor(ctx: Group<P>) {
    this.ctx = ctx;
  }

  distributeKey = async (nrShares: number, threshold: number, privateKey: PrivateKey<P>): Promise<KeySharing<P>> => {
    const { polynomial } = await shamir(this.ctx).shareSecret(nrShares, threshold, privateKey.secret);
    return new KeySharing(this.ctx, nrShares, threshold, polynomial);
  }

  reconstructKey = async (shares: PrivateShare<P>[], threshold?: number): Promise<PrivateKey<P>> => {
    if (threshold && shares.length < threshold) throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
    const secretShares = shares.map(({ secret: value, index }) => { return { value, index } });
    const secret = await shamir(this.ctx).reconstructSecret(secretShares);
    return new PrivateKey(this.ctx, leInt2Buff(secret));
  }

  reconstructPublic = async (shares: PublicShare<P>[], threshold?: number): Promise<PublicKey<P>> => {
    // TODO: Include validation
    if (threshold && shares.length < threshold) throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
    const pubShares = shares.map(({ pub: value, index }) => { return { value, index } });
    const pub = await shamir(this.ctx).reconstructPublic(pubShares);
    return new PublicKey(this.ctx, pub);
  }

  // TODO: Include indexed nonces option?
  verifyPartialDecryptors = async (
    ciphertext: ElgamalCiphertext<P>,
    publicShares: PublicShare<P>[],
    shares: PartialDecryptor<P>[],
    opts?: { threshold?: number, raiseOnInvalid?: boolean },
  ): Promise<{ flag: boolean, indexes: number[]}> => {
    const threshold = opts ? opts.threshold : undefined;
    if (threshold && shares.length < threshold) throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
    const selectPublicShare = (index: number, shares: PublicShare<P>[]) => {
      const selected = shares.filter(share => share.index == index)[0];
      if (!selected) throw new Error('No share with index');
      return selected;
    }
    let flag = true;
    let indexes = [];
    const { ctx } = this;
    const raiseOnInvalid = opts ? (opts.raiseOnInvalid || false) : false;
    for (const partialDecryptor of shares) {
      const publicShare = selectPublicShare(partialDecryptor.index, publicShares);
      const verified = await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor, {
        raiseOnInvalid: false,
      });
      if (!verified && raiseOnInvalid)
        throw new Error(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
      flag &&= verified;
      if(!verified) indexes.push(partialDecryptor.index);
    }
    return { flag, indexes };
  }

  reconstructDecryptor = async (
    shares: PartialDecryptor<P>[],
    opts?: { threshold?: number, publicShares?: PublicShare<P>[] }
  ): Promise<P> => {
    // TODO: Include validation
    const threshold = opts ? opts.threshold : undefined;
    if (threshold && shares.length < threshold) throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
    const { order, neutral, operate, combine } = this.ctx;
    const qualifiedIndexes = shares.map(share => share.index);
    let acc = neutral;
    for (const share of shares) {
      const { value, index } = share;
      const lambda = shamir(this.ctx).computeLambda(index, qualifiedIndexes);
      const curr = await operate(lambda, value);
      acc = await combine(acc, curr);
    }
    return acc;
  }

  thresholdDecrypt = async(
    ciphertext: ElgamalCiphertext<P>,
    shares: PartialDecryptor<P>[],
    opts: {
      scheme: ElgamalScheme,
      mode?: AesMode,
      algorithm?: Algorithm,
      threshold?: number,
    },
  ): Promise<Uint8Array> => {
    let { scheme, mode, algorithm, threshold } = opts;
    // TODO: Include public schares option for validation
    const decryptor = await this.reconstructDecryptor(shares, { threshold });
    switch (scheme) {
      case ElgamalSchemes.IES:
        mode = mode || AesModes.DEFAULT;
        algorithm = algorithm || Algorithms.DEFAULT;
        return elgamal[ElgamalSchemes.IES](this.ctx, mode, algorithm).decryptWithDecryptor(
          ciphertext, decryptor,
        );
      case ElgamalSchemes.KEM:
        mode = mode || AesModes.DEFAULT;
        return elgamal[ElgamalSchemes.KEM](this.ctx, mode).decryptWithDecryptor(
          ciphertext, decryptor,
        );
      case ElgamalSchemes.PLAIN:
        return elgamal[ElgamalSchemes.PLAIN](this.ctx).decryptWithDecryptor(
          ciphertext, decryptor
        );
    }
  }
}
