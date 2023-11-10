import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { SigmaProof } from '../sigma';
import { PublicKey, PublicShare } from './public';
import { Polynomial } from '../polynomials';
import { SecretShare, PartialDecryptor } from '../shamir';
import { Label } from '../types';
import { Messages } from './enums';
import { leInt2Buff } from '../utils';

const backend = require('../backend');
const sigma = require('../sigma');
const elgamal = require('../elgamal');
const shamir = require('../shamir');


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

  async isEqual<Q extends Point>(other: PrivateKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.isEqual(other.ctx)) &&
      // TODO: Constant time bytes comparison
      (this.scalar == other.scalar)
    );
  }

  async publicPoint(): Promise<P> {
    const { ctx, scalar } = this;
    return ctx.operate(scalar, ctx.generator);
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

  async proveIdentity(opts?: { algorithm?: Algorithm, nonce?: Uint8Array }): Promise<SigmaProof<P>> {
    const { ctx, scalar } = this;
    const pub = await ctx.operate(scalar, ctx.generator);
    return sigma.proveDlog(ctx, scalar, { u: ctx.generator, v: pub }, opts);
  }

  async decrypt(ciphertext: Ciphertext<P>): Promise<P> {
    return elgamal.decrypt(this.ctx, ciphertext, { secret: this.scalar });
  }

  async verifyEncryption(
    ciphertext: Ciphertext<P>,
    proof: SigmaProof<P>,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
  ): Promise<boolean> {
    const verified = await elgamal.verifyEncryption(this.ctx, ciphertext, proof, opts);
    if (!verified) throw new Error(Messages.INVALID_ENCRYPTION_PROOF);
    return verified;
  }

  async proveDecryptor(
    ciphertext: Ciphertext<P>,
    decryptor: P,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array }
  ): Promise<SigmaProof<P>> {
    const { ctx, scalar } = this;
    return elgamal.proveDecryptor(ctx, ciphertext, scalar, decryptor, opts);
  }

  async generateDecryptor(
    ciphertext: Ciphertext<P>,
    opts?: { noProof?: boolean, algorithm?: Algorithm },
  ): Promise<{ decryptor: P, proof?: SigmaProof<P> }> {
    const { ctx, scalar: secret } = this;
    const decryptor = await elgamal.generateDecryptor(ctx, secret, ciphertext);
    const noProof = opts ? opts.noProof : false;
    if (noProof) return { decryptor };
    const proof = await elgamal.proveDecryptor(ctx, ciphertext, secret, decryptor, opts);
    return { decryptor, proof };
  }

  async distribute(opts: { nrShares: number, threshold: number }): Promise<KeyDistribution<P>> {
    const { nrShares, threshold } = opts;
    const { ctx, scalar: secret } = this;
    const { secretShares, polynomial, commitments } = await shamir.shareSecret(
      ctx, secret, nrShares, threshold
    );
    const privateShares = secretShares.map(
      ({ value, index }: SecretShare<P>) => new PrivateShare(ctx, value, index)
    );
    return new KeyDistribution(threshold, privateShares, polynomial, commitments);
  }

  static async fromShares<Q extends Point>(qualifiedSet: PrivateShare<Q>[]): Promise<PrivateKey<Q>> {
    if (qualifiedSet.length < 1) throw new Error(Messages.AT_LEAST_ONE_SHARE_NEEDED);
    const ctx = qualifiedSet[0].ctx;
    const secretShares = qualifiedSet.map(({ scalar: value, index }) => { return {
        value, index
      };
    });
    const secret = await shamir.reconstructSecret(ctx, secretShares);
    return new PrivateKey(ctx, leInt2Buff(secret));
  }
}


export interface SerializedPrivateShare extends SerializedPrivateKey {
  index: number;
}

export class PrivateShare<P extends Point> extends PrivateKey<P> {
  index: number;

  constructor(ctx: Group<P>, scalar: bigint, index: number) {
    super(ctx, leInt2Buff(scalar));
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

  async generatePartialDecryptor(ciphertext: Ciphertext<P>): Promise<PartialDecryptor<P>> {
    const { ctx, scalar: value, index } = this;
    return await shamir.generatePartialDecryptor(ctx, ciphertext, { value, index });
  }
};

export class KeyDistribution<P extends Point> {
  threshold: number;
  privateShares: PrivateShare<P>[];
  polynomial: Polynomial<P>;
  commitments: P[];

  constructor(
    threshold: number,
    privateShares: PrivateShare<P>[],
    polynomial: Polynomial<P>,
    commitments: P[],
  ) {
    this.threshold = threshold;
    this.privateShares = privateShares;
    this.polynomial = polynomial;
    this.commitments = commitments;
  }

  publicShares = async (): Promise<PublicShare<P>[]> => {
    const shares = [];
    for (const [index, privateShare] of this.privateShares.entries()) {
      shares.push(await privateShare.publicShare());
    }
    return shares;
  }
}
