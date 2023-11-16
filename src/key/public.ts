import { Group, Point } from '../backend/abstract';
import { ElGamalCiphertext } from '../elgamal';
import { Label } from '../types';
import { SigmaProof } from '../sigma';
import { Messages } from './enums';
import { PartialDecryptor } from '../common';

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

  async verifyIdentity(proof: SigmaProof<P>, opts?: { nonce?: Uint8Array }): Promise<boolean> {
    const { ctx, point: pub } = this;
    const verified = await sigma.verifyDlog(ctx, { u: ctx.generator, v: pub }, proof, opts);
    if (!verified) throw new Error(Messages.INVALID_IDENTITY_PROOF);
    return verified;
  }

  async encrypt(message: P): Promise<{
    ciphertext: ElGamalCiphertext<P>, randomness: bigint, decryptor: P
  }> {
    return elgamal.encrypt(this.ctx, message, this.point);
  }

  async proveEncryption(
    ciphertext: ElGamalCiphertext<P>,
    randomness: bigint,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array }
  ): Promise<SigmaProof<P>> {
    const { ctx } = this;
    return sigma.proveDlog(ctx, randomness, { u: ctx.generator, v: ciphertext.beta }, opts);
  }

  async verifyDecryptor(
    ciphertext: ElGamalCiphertext<P>,
    decryptor: P,
    proof: SigmaProof<P>,
    opts?: { nonce?: Uint8Array, raiseOnInvalid?: boolean }
  ): Promise<boolean> {
    const { ctx, point: pub } = this;
    const verified = await sigma.verifyDDH(ctx, { u: ciphertext.beta, v: pub, w: decryptor }, proof, opts);
    const raiseOnInvalid = opts ?
      (opts.raiseOnInvalid === undefined ? true : opts.raiseOnInvalid) :
      true;
    if (!verified && raiseOnInvalid) throw new Error(Messages.INVALID_DECRYPTOR_PROOF);
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
  value: P;
  index: number;

  constructor(ctx: Group<P>, point: P, index: number) {
    super(ctx, point);
    this.value = point;
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

  async verifyPartialDecryptor(
    ciphertext: ElGamalCiphertext<P>,
    partialDecryptor: PartialDecryptor<P>,
    opts?: { nonce?: Uint8Array, raiseOnInvalid?: boolean },
  ): Promise<boolean> {
    const { ctx, index } = this;
    const { value: decryptor, proof } = partialDecryptor;
    const nonce = opts ? opts.nonce : undefined;
    const verified = await this.verifyDecryptor(ciphertext, decryptor, proof, { nonce, raiseOnInvalid: false });
    const raiseOnInvalid = opts ?
      (opts.raiseOnInvalid === undefined ? true : opts.raiseOnInvalid) :
      true;
    if (!verified && raiseOnInvalid) throw new Error(Messages.INVALID_PARTIAL_DECRYPTOR);
    return verified;
  }
};
