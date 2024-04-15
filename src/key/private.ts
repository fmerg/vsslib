import { Group, Point } from '../backend/abstract';
import { SigmaProof } from '../sigma';
import { PublicKey, PublicShare } from './public';
import { ScalarShare } from '../shamir';
import { PartialDecryptor } from '../tds';
import { BaseShare, BaseSharing } from '../vss';
import { Label } from '../types';
import { Messages } from './enums';
import { leInt2Buff } from '../utils';
import schnorr from '../schnorr';
import { SchnorrSignature } from '../schnorr';
const backend = require('../backend');
const sigma = require('../sigma');
import { dlog, ddh } from '../sigma';
import { ElgamalScheme, AesMode, Algorithm } from '../types';
import { Algorithms, ElgamalSchemes } from '../enums';
import { Ciphertext, plain, kem, ies } from '../elgamal';
const elgamal = require('../elgamal');
import shamir from '../shamir';


export type SerializedPrivateKey = {
  value: string;
  system: Label;
}


export class PrivateKey<P extends Point> {
  ctx: Group<P>;
  bytes: Uint8Array;
  scalar: bigint;

  constructor(ctx: Group<P>, bytes: Uint8Array) {
    this.ctx = ctx;
    this.bytes = bytes;
    this.scalar = ctx.leBuff2Scalar(bytes);
  }

  static async fromBytes(ctx: Group<Point>, bytes: Uint8Array): Promise<PrivateKey<Point>> {
    await ctx.validateBytes(bytes);
    return new PrivateKey(ctx, bytes);
  }

  static async fromScalar(ctx: Group<Point>, scalar: bigint): Promise<PrivateKey<Point>> {
    await ctx.validateScalar(scalar);
    return new PrivateKey(ctx, leInt2Buff(scalar));
  }

  serialize = (): SerializedPrivateKey => {
    const { ctx, bytes } = this;
    return { value: Buffer.from(bytes).toString('hex'), system: ctx.label };
  }

  static async deserialize(serialized: SerializedPrivateKey): Promise<PrivateKey<Point>> {
    const { value, system: label } = serialized;
    const ctx = backend.initGroup(label);
    const bytes = Uint8Array.from(Buffer.from(value, 'hex'));
    return PrivateKey.fromBytes(ctx, bytes);
  }

  async equals<Q extends Point>(other: PrivateKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.equals(other.ctx)) &&
      // TODO: Constant time bytes comparison
      (this.scalar == other.scalar)
    );
  }

  async publicKey(): Promise<PublicKey<P>> {
    const { ctx, scalar } = this;
    const point = await ctx.operate(scalar, ctx.generator);
    return new PublicKey(ctx, point);
  }

  async diffieHellman(pub: PublicKey<P>): Promise<P> {
    const { ctx, scalar } = this;
    await ctx.validatePoint(pub.point);
    return ctx.operate(scalar, pub.point);
  }

  async sign(message: Uint8Array, opts?: { nonce?: Uint8Array, algorithm?: Algorithm }): Promise<SchnorrSignature<P>> {
    const { ctx, scalar: secret } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message, nonce);
    return signature;
  }

  async proveIdentity(opts?: { algorithm?: Algorithm, nonce?: Uint8Array }): Promise<SigmaProof<P>> {
    const { ctx, scalar: secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const proof = dlog(ctx, algorithm).prove(secret, { u: ctx.generator, v: pub }, nonce);
    return proof;
  }

  async decrypt<A extends object>(ciphertext: Ciphertext<A, P>): Promise<Uint8Array> {
    const scheme = elgamal.resolveScheme(ciphertext);
    return elgamal[scheme](this.ctx).decrypt(ciphertext, this.scalar);
  }

  async verifyEncryption<A>(
    ciphertext: Ciphertext<A, P>,
    proof: SigmaProof<P>,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
  ): Promise<boolean> {
    const { ctx } = this;
    const nonce = opts ? opts.nonce : undefined;
    const verified = await dlog(ctx).verify({ u: ctx.generator, v: ciphertext.beta }, proof, nonce);
    if (!verified) throw new Error(Messages.INVALID_ENCRYPTION_PROOF);
    return verified;
  }

  async proveDecryptor<A>(
    ciphertext: Ciphertext<A, P>,
    decryptor: P,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array }
  ): Promise<SigmaProof<P>> {
    const { ctx, scalar: secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const proof = await ddh(ctx, algorithm).prove(secret, { u: ciphertext.beta, v: pub, w: decryptor }, nonce);
    return proof;
  }

  async generateDecryptor<A>(
    ciphertext: Ciphertext<A, P>,
    opts?: { noProof?: boolean, algorithm?: Algorithm },
  ): Promise<{ decryptor: P, proof?: SigmaProof<P> }> {
    const { ctx, scalar: secret } = this;
    const decryptor = await ctx.operate(secret, ciphertext.beta);
    const noProof = opts ? opts.noProof : false;
    if (noProof) return { decryptor };
    const proof = await this.proveDecryptor(ciphertext, decryptor, opts);
    return { decryptor, proof };
  }

  async distribute(nrShares: number, threshold: number): Promise<KeySharing<P>> {
    const { ctx, scalar: secret } = this;
    const { polynomial } = await shamir(ctx).distribute(secret, nrShares, threshold);
    return new KeySharing(ctx, nrShares, threshold, polynomial);
  }

  static async fromShares<Q extends Point>(qualifiedSet: PrivateShare<Q>[]): Promise<PrivateKey<Q>> {
    if (qualifiedSet.length < 1) throw new Error(Messages.AT_LEAST_ONE_SHARE_NEEDED);
    const ctx = qualifiedSet[0].ctx;
    const secretShares = qualifiedSet.map(({ scalar: value, index }) => { return {
        value, index
      };
    });
    const secret = await shamir(ctx).reconstructSecret(secretShares);
    return new PrivateKey(ctx, leInt2Buff(secret));
  }
}


export interface SerializedPrivateShare extends SerializedPrivateKey {
  index: number;
}

export class PrivateShare<P extends Point> extends PrivateKey<P> implements BaseShare<bigint>{
  value: bigint;
  index: number;

  constructor(ctx: Group<P>, scalar: bigint, index: number) {
    super(ctx, leInt2Buff(scalar));
    this.value = this.scalar;
    this.index = index;
  }

  serialize = (): SerializedPrivateShare => {
    const { ctx, bytes, index } = this;
    return { value: Buffer.from(bytes).toString('hex'), system: ctx.label, index };
  }

  static async deserialize(serialized: SerializedPrivateShare): Promise<PrivateKey<Point>> {
    const { value, system: label, index } = serialized;
    const ctx = backend.initGroup(label);
    const bytes = Uint8Array.from(Buffer.from(value, 'hex'));
    await ctx.validateBytes(bytes);
    return new PrivateShare(ctx, ctx.leBuff2Scalar(bytes), index);
  }

  async publicShare(): Promise<PublicShare<P>> {
    const { ctx, index } = this;
    const point = await ctx.operate(this.scalar, ctx.generator);
    return new PublicShare(ctx, point, index);
  }

  async verifyFeldmann(commitments: P[]): Promise<boolean> {
    const { ctx, value, index } = this;
    const secretShare = new ScalarShare(value, index);
    const verified = await shamir(ctx).verifyFeldmann(secretShare, commitments);
    if (!verified) throw new Error('Invalid share');
    return verified;
  }

  async verifyPedersen(binding: bigint, pub: P, commitments: P[]): Promise<boolean> {
    const { ctx, value, index } = this;
    const secretShare = new ScalarShare(value, index);
    const verified = await shamir(ctx).verifyPedersen(secretShare, binding, pub, commitments);
    if (!verified) throw new Error('Invalid share');
    return verified;
  }

  async generatePartialDecryptor<A>(
    ciphertext: Ciphertext<A, P>,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
  ): Promise<PartialDecryptor<P>> {
    const { ctx, index } = this;
    const { decryptor } = await this.generateDecryptor(ciphertext, { noProof: true });
    const proof = await this.proveDecryptor(ciphertext, decryptor, opts);
    return { value: decryptor, index, proof}
  }
};

export class KeySharing<P extends Point> extends BaseSharing<
  bigint,
  P,
  PrivateShare<P>,
  PublicShare<P>
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
      const value = await operate(evaluate(index), generator);
      shares.push(new PublicShare(this.ctx, value, index));
    }
    return shares;
  }
}
