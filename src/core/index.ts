import { Point, Group } from '../backend/abstract';
import { Label } from '../types';
import { PrivateKey, PublicKey, KeyPair, PrivateShare, PublicShare } from '../key';
import { PartialDecryptor } from '../shamir';
import { assertLabel } from '../utils/checkers';
import { leInt2Buff } from '../utils';
import { Ciphertext } from '../elgamal/core';

const shamir = require('../shamir');
const elgamal = require('../elgamal');
const backend = require('../backend');


export class Combiner<P extends Point> {
  ctx: Group<P>;

  constructor(ctx: Group<P>) {
    this.ctx = ctx;
  }

  async reconstructKey(shares: PrivateShare<P>[]): Promise<KeyPair<P>> {
    // TODO: Input validation
    const secretShares = shares.map(({ scalar: value, index }) => { return {
        value, index
      };
    });
    const secret = await shamir.reconstructSecret(this.ctx, secretShares);
    const privateKey = new PrivateKey(this.ctx, leInt2Buff(secret));
    const publicKey = await privateKey.publicKey();
    return { privateKey, publicKey };
  }

  async reconstructPublic(shares: PublicShare<P>[]): Promise<PublicKey<P>> {
    // TODO: Input validation
    const pointShares = shares.map(({ point: value, index }) => { return {
        value, index
      };
    });
    const point = await shamir.reconstructPublic(this.ctx, pointShares);
    return new PublicKey(this.ctx, point);
  }

  async validatePartialDecryptors(
    ciphertext: Ciphertext<P>,
    publicShares: PublicShare<P>[],
    shares: PartialDecryptor<P>[]
  ): Promise<[boolean, number[]]> {
    // TODO: Input validation
    const selectPublicShare = (index: number, shares: PublicShare<P>[]) => shares.filter(
      share => share.index == index)[0];  // Handle undefined
    let flag = true;
    let indexes = [];
    for (const { value: decryptor, index, proof } of shares) {
      const { point: pub } = selectPublicShare(index, publicShares);
      const verified = await elgamal.verifyDecryptor(this.ctx, ciphertext, pub, decryptor, proof);
      flag &&= verified;
      if(!verified) indexes.push(index);
    }
    return [flag, indexes];
  }

  async reconstructDecryptor(shares: PartialDecryptor<P>[]): Promise<P> {
    // TODO: Input validation
    return shamir.reconstructDecryptor(this.ctx, shares);
  }

  async decrypt(ciphertext: Ciphertext<P>, shares: PartialDecryptor<P>[]): Promise<P> {
    // TODO: Input validation
    return shamir.decrypt(this.ctx, ciphertext, shares);
  }
}

export function initCombiner(label: Label): Combiner<Point> {
  assertLabel(label);
  const group = backend.initGroup(label);
  return new Combiner(group);
}
