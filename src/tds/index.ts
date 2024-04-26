import { Point, Group } from '../backend/abstract';
import { Label } from '../types';
import { PrivateKey, PublicKey, KeyPair, PrivateShare, PublicShare } from '../key';
import { BaseShare } from '../vss';
import { assertLabel } from '../utils/checkers';
import { leInt2Buff } from '../utils';
import { SigmaProof } from '../core/sigma';

import { Ciphertext, plain, kem, ies } from '../core/elgamal';
import { ElgamalScheme, AesMode, Algorithm } from '../types';
import { Algorithms, ElgamalSchemes } from '../enums';

import shamir from '../core/shamir';
const backend = require('../backend');
const elgamal = require('../core/elgamal');



export class PartialDecryptor<P extends Point> implements BaseShare<P> {
  value: P;
  index: number;
  proof: SigmaProof<P>;

  constructor(value: P, index: number, proof: SigmaProof<P>) {
    this.value = value;
    this.index = index;
    this.proof = proof;
  }
};


export class Combiner<P extends Point> {
  ctx: Group<P>;
  threshold: number;

  constructor(ctx: Group<P>, threshold: number) {
    if (threshold < 1) throw new Error('Threshold parameter must be >= 1');
    this.ctx = ctx;
    this.threshold = threshold;
  }

  validateNrShares(
    shares: (PrivateShare<P> | PublicShare<P> | PartialDecryptor<P>)[],
    opts?: { threshold?: number, skipThreshold?: boolean},
  ) {
    const threshold = opts ? (opts.threshold || this.threshold ) : this.threshold;
    const skipThreshold = opts ? opts.skipThreshold : false;
    if (!skipThreshold && shares.length < threshold)
      throw new Error('Nr shares less than threshold');
  }

  async reconstructKey(
    shares: PrivateShare<P>[],
    opts?: { threshold?: number, skipThreshold?: boolean }
  ): Promise<KeyPair<P>> {
    this.validateNrShares(shares, opts);
    const secretShares = shares.map(({ scalar: value, index }) => { return {
        value, index
      };
    });
    const secret = await shamir(this.ctx).reconstructSecret(secretShares);
    const privateKey = new PrivateKey(this.ctx, leInt2Buff(secret));
    const publicKey = await privateKey.publicKey();
    return { privateKey, publicKey };
  }

  async reconstructPublic(
    shares: PublicShare<P>[],
    opts?: { threshold?: number, skipThreshold?: boolean }
  ): Promise<PublicKey<P>> {
    this.validateNrShares(shares, opts);
    const pointShares = shares.map(({ point: value, index }) => { return {
        value, index
      };
    });
    const point = await shamir(this.ctx).reconstructPublic(pointShares);
    return new PublicKey(this.ctx, point);
  }

  async verifyPartialDecryptor<A>(
    ciphertext: Ciphertext<A, P>,
    publicShare: PublicShare<P>,
    share: PartialDecryptor<P>,
    opts?: { nonce?: Uint8Array },
  ): Promise<boolean> {
    const verified = await publicShare.verifyPartialDecryptor(ciphertext, share, opts);
    return verified;
  }

  // TODO: Include indexed nonces option?
  async verifyPartialDecryptors<A>(
    ciphertext: Ciphertext<A, P>,
    publicShares: PublicShare<P>[],
    shares: PartialDecryptor<P>[],
    opts?: { raiseOnInvalid?: boolean, threshold?: number, skipThreshold?: boolean },
  ): Promise<{ flag: boolean, indexes: number[]}> {
    this.validateNrShares(shares, opts);
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
        throw new Error('Invalid partial decryptor');
      flag &&= verified;
      if(!verified) indexes.push(partialDecryptor.index);
    }
    return { flag, indexes };
  }

  async reconstructDecryptor(
    shares: PartialDecryptor<P>[],
    opts?: { threshold?: number, skipThreshold?: boolean, publicShares?: PublicShare<P>[]},
  ): Promise<P> {
    this.validateNrShares(shares, opts);
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

  async decrypt<A extends object>(
    ciphertext: Ciphertext<A, P>,
    shares: PartialDecryptor<P>[],
    opts?: { threshold?: number, skipThreshold?: boolean },
  ): Promise<Uint8Array> {
    // TODO?
    const decryptor = await this.reconstructDecryptor(shares, opts);
    const scheme = elgamal.resolveScheme(ciphertext);
    return elgamal[scheme](this.ctx).decryptWithDecryptor(ciphertext, decryptor);
  }
}


export default function<P extends Point>(ctx: Group<P>, threshold: number): Combiner<P> {
  return new Combiner(ctx, threshold);
}
