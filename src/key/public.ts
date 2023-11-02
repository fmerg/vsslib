import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { Label } from '../types';
import { DlogProof } from '../sigma';
import { Messages } from './enums';

const backend = require('../backend');
const sigma = require('../sigma');
const elgamal = require('../elgamal');
const shamir = require('../shamir');


export type SerializedPublicKey = {
  value: string;
  system: Label;
}


export class PublicKey<P extends Point> {
  ctx: Group<P>;
  bytes: Uint8Array;
  point: P;

  constructor(ctx: Group<P>, point: P) {
    this.ctx = ctx;
    this.bytes = point.toBytes();
    this.point = point;
  }

  static async fromPoint(ctx: Group<Point>, point: Point): Promise<PublicKey<Point>> {
    await ctx.validatePoint(point);
    return new PublicKey(ctx, point);
  }

  serialize = (): SerializedPublicKey => {
    const { ctx, point } = this;
    return { value: point.toHex(), system: ctx.label };
  }

  static async deserialize(serialized: SerializedPublicKey): Promise<PublicKey<Point>> {
    const { value, system: label } = serialized;
    const ctx = backend.initGroup(label);
    return PublicKey.fromPoint(ctx, ctx.unhexify(value));
  }

  async isEqual<Q extends Point>(other: PublicKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.isEqual(other.ctx)) &&
      // TODO: Constant time bytes comparison
      (await this.point.isEqual(other.point))
    );
  }

  async verifyIdentity(proof: DlogProof<P>): Promise<boolean> {
    const { ctx, point: pub } = this;
    const verified = await sigma.verifyDlog(ctx, ctx.generator, pub, proof);
    if (!verified) throw new Error(Messages.INVALID_IDENTITY_PROOF);
    return verified;
  }

  async encrypt(message: P): Promise<{
    ciphertext: Ciphertext<P>, randomness: bigint, decryptor: P
  }> {
    return elgamal.encrypt(this.ctx, message, this.point);
  }

  async proveEncryption(
    ciphertext: Ciphertext<P>,
    randomness: bigint,
    opts?: { algorithm?: Algorithm }
  ): Promise<DlogProof<P>> {
    return elgamal.proveEncryption(this.ctx, ciphertext, randomness, opts);
  }

  async verifyDecryptor(
    ciphertext: Ciphertext<P>,
    decryptor: P,
    proof: DlogProof<P>,
  ): Promise<boolean> {
    const { ctx, point: pub } = this;
    const verified = await elgamal.verifyDecryptor(ctx, ciphertext, pub, decryptor, proof);
    if (!verified) throw new Error(Messages.INVALID_DECRYPTOR_PROOF);
    return verified;
  }

  static async fromShares<Q extends Point>(qualifiedSet: PublicShare<Q>[]): Promise<PublicKey<Q>> {
    if (qualifiedSet.length < 1) throw new Error(Messages.AT_LEAST_ONE_SHARE_NEEDED);
    const ctx = qualifiedSet[0].ctx;
    const pointShares = qualifiedSet.map(({ point: value, index }) => { return {
        value, index
      };
    });
    const point = await shamir.reconstructPublic(ctx, pointShares);
    return new PublicKey(ctx, point);
  }
}


export interface SerializedPublicShare extends SerializedPublicKey {
  index: number;
}


export class PublicShare<P extends Point> extends PublicKey<P> {
  index: number;

  constructor(ctx: Group<P>, point: P, index: number) {
    super(ctx, point);
    this.index = index;
  }

  serialize = (): SerializedPublicShare => {
    const { ctx, point, index } = this;
    return { value: point.toHex(), system: ctx.label, index };
  }

  static async deserialize(serialized: SerializedPublicShare): Promise<PublicKey<Point>> {
    const { value, system: label, index } = serialized;
    const ctx = backend.initGroup(label);
    const point = ctx.unhexify(value);
    await ctx.validatePoint(point);
    return new PublicShare(ctx, point, index);
  }
};
