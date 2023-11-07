import { Point, Group } from '../backend/abstract';
import { Label } from '../types';
import { PrivateKey, PublicKey, KeyPair, PrivateShare, PublicShare } from '../key';
import { PartialDecryptor } from '../types';
import { assertLabel } from '../utils/checkers';
import { leInt2Buff } from '../utils';
import { Ciphertext } from '../elgamal/core';
import { Share, computeLambda } from '../shamir/common';

const shamir = require('../shamir');
const elgamal = require('../elgamal');
const backend = require('../backend');


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
    const secret = await shamir.reconstructSecret(this.ctx, secretShares);
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
    const point = await shamir.reconstructPublic(this.ctx, pointShares);
    return new PublicKey(this.ctx, point);
  }

  async validatePartialDecryptor(
    ciphertext: Ciphertext<P>,
    publicShare: PublicShare<P>,
    share: PartialDecryptor<P>,
    opts?: { nonce?: Uint8Array },
  ): Promise<boolean> {
    const { value: decryptor, proof } = share;
    const { point: pub } = publicShare;
    const verified = await elgamal.verifyDecryptor(this.ctx, ciphertext, pub, decryptor, proof, opts);
    if (!verified) throw new Error('Invalid partial decryptor');
    return verified;
  }

  // TODO: Include indexed nonces option?
  async validatePartialDecryptors(
    ciphertext: Ciphertext<P>,
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
    for (const { value: decryptor, index, proof } of shares) {
      const { point: pub } = selectPublicShare(index, publicShares);
      const verified = await elgamal.verifyDecryptor(ctx, ciphertext, pub, decryptor, proof);
      if (raiseOnInvalid && !verified)
        throw new Error('Invalid partial decryptor detected');
      flag &&= verified;
      if(!verified) indexes.push(index);
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
      const lambda = computeLambda(index, qualifiedIndexes, order);
      const curr = await operate(lambda, value);
      acc = await combine(acc, curr);
    }
    return acc;
  }

  async decrypt(
    ciphertext: Ciphertext<P>,
    shares: PartialDecryptor<P>[],
    opts?: { threshold?: number, skipThreshold?: boolean, publicShares?: PublicShare<P>[] },
  ): Promise<P> {
    this.validateNrShares(shares, opts);
    const publicShares = opts ? opts.publicShares : undefined;
    if (publicShares) {
      const { flag, indexes } = await this.validatePartialDecryptors(
        ciphertext, publicShares, shares
      );
      if (!flag) throw new Error('Invalid partial decryptor detected');
    }
    const decryptor = await this.reconstructDecryptor(shares, opts);
    return elgamal.decrypt(this.ctx, ciphertext, { decryptor });
  }
}

export function initCombiner(opts: { label: Label, threshold: number }): Combiner<Point> {
  const { label, threshold } = opts;
  assertLabel(label);
  const group = backend.initGroup(label);
  return new Combiner(group, threshold);
}
