import { Group, Point } from '../backend/abstract';
import { SigmaProof } from '../core/sigma';
import { Messages } from './enums';
import { PartialDecryptor } from '../tds';
import {
  ElgamalSchemes, ElgamalScheme,
  AesMode, AesModes,
  Algorithms, Algorithm,
  SignatureSchemes,
  Label,
} from '../schemes';
import { dlog, ddh } from '../core/sigma';
import signer from '../core/signer';
import { Signature } from '../core/signer/base';
import { SchnorrSignature } from '../core/signer/schnorr';
const backend = require('../backend');
const sigma = require('../core/sigma');
import elgamal from '../core/elgamal';
import { ElgamalCiphertext } from '../core/elgamal';
import shamir from '../core/shamir';


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

  async equals<Q extends Point>(other: PublicKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.equals(other.ctx)) &&
      // TODO: Constant time bytes comparison
      (await this.point.equals(other.point))
    );
  }

  async verifySignature(
    message: Uint8Array,
    signature: Signature<P>,
    opts: { nonce?: Uint8Array, algorithm?: Algorithm },
  ): Promise<boolean> {
    const { ctx, point: pub } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature as SchnorrSignature<P>, nonce
    );
    if (!verified) throw new Error('Invalid signature');
    return verified;
  }

  async verifyIdentity(proof: SigmaProof<P>, nonce?: Uint8Array): Promise<boolean> {
    const { ctx, point: pub } = this;
    const verified = await dlog(ctx, Algorithms.DEFAULT).verify({ u: ctx.generator, v: pub }, proof, nonce);
    if (!verified) throw new Error(Messages.INVALID_IDENTITY_PROOF);
    return verified;
  }

  async encrypt(
    message: Uint8Array,
    opts: { scheme: ElgamalScheme, mode?: AesMode, algorithm?: Algorithm }
  ): Promise<{
    ciphertext: ElgamalCiphertext<P>,
    randomness: bigint,
    decryptor: P,
  }> {
    let { scheme, mode, algorithm } = opts;
    mode = mode || AesModes.DEFAULT;
    algorithm = algorithm || Algorithms.DEFAULT;
    return elgamal(this.ctx, scheme, mode, algorithm).encrypt(message, this.point);
  }

  async proveEncryption(
    ciphertext: ElgamalCiphertext<P>,
    randomness: bigint,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array }
  ): Promise<SigmaProof<P>> {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const proof = dlog(ctx, algorithm).prove(randomness, { u: ctx.generator, v: ciphertext.beta }, nonce);
    return proof;
  }

  async verifyDecryptor(
    ciphertext: ElgamalCiphertext<P>,
    decryptor: P,
    proof: SigmaProof<P>,
    opts?: { nonce?: Uint8Array, raiseOnInvalid?: boolean }
  ): Promise<boolean> {
    const { ctx, point: pub } = this;
    const nonce = opts ? (opts.nonce) : undefined;
    const verified = await ddh(ctx, Algorithms.DEFAULT).verify({ u: ciphertext.beta, v: pub, w: decryptor }, proof, nonce);
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
    const point = await shamir(ctx).reconstructPublic(pointShares);
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

  async verifyPartialDecryptor<A>(
    ciphertext: ElgamalCiphertext<P>,
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
