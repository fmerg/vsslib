import { Group, Point } from '../backend/abstract';
import { SigmaProof } from '../crypto/sigma';
import { PublicKey, PublicShare } from './public';
import { SecretShare } from '../shamir';
import { PartialDecryptor } from '../core';
import { BaseShare, BaseSharing } from '../base';
import { Messages } from './enums';
import { leInt2Buff } from '../crypto/bitwise';
import signer from '../crypto/signer';
import { Signature } from '../crypto/signer/base';
const backend = require('../backend');
const sigma = require('../crypto/sigma');
import { dlog, ddh } from '../crypto/sigma';
import {
  Algorithms, Algorithm,
  AesModes, AesMode,
  ElgamalSchemes, ElgamalScheme,
  SignatureSchemes,
  Label,
} from '../schemes';
const elgamal = require('../crypto/elgamal');
import { ElgamalCiphertext } from '../crypto/elgamal';
import { PlainCiphertext } from '../crypto/elgamal/plain';
import { KemCiphertext } from '../crypto/elgamal/kem';
import { IesCiphertext } from '../crypto/elgamal/ies';
import shamir from '../shamir';


export type SerializedPrivateKey = {
  value: string;
  system: Label;
}


export class PrivateKey<P extends Point> {
  ctx: Group<P>;
  bytes: Uint8Array;
  secret: bigint;

  constructor(ctx: Group<P>, bytes: Uint8Array) {
    this.ctx = ctx;
    this.bytes = bytes;
    this.secret = ctx.leBuff2Scalar(bytes);
  }

  static async fromBytes(ctx: Group<Point>, bytes: Uint8Array): Promise<PrivateKey<Point>> {
    await ctx.validateBytes(bytes);
    return new PrivateKey(ctx, bytes);
  }

  static async fromScalar(ctx: Group<Point>, secret: bigint): Promise<PrivateKey<Point>> {
    await ctx.validateScalar(secret);
    return new PrivateKey(ctx, leInt2Buff(secret));
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
      (this.secret == other.secret)
    );
  }

  async publicKey(): Promise<PublicKey<P>> {
    const { ctx, secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    return new PublicKey(ctx, pub);
  }

  async diffieHellman(publicKey: PublicKey<P>): Promise<P> {
    const { ctx, secret } = this;
    await ctx.validatePoint(publicKey.pub);
    return ctx.operate(secret, publicKey.pub);
  }

  async sign(
    message: Uint8Array,
    opts?: { nonce?: Uint8Array, algorithm?: Algorithm }
  ): Promise<Signature<P>> {
    const { ctx, secret: secret } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const signature = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).signBytes(
      secret, message, nonce
    );
    return signature;
  }

  async proveIdentity(opts?: { algorithm?: Algorithm, nonce?: Uint8Array }): Promise<SigmaProof<P>> {
    const { ctx, secret: secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const proof = dlog(ctx, algorithm).prove(secret, { u: ctx.generator, v: pub }, nonce);
    return proof;
  }

  async decrypt(
    ciphertext: ElgamalCiphertext<P>,
    opts: { scheme: ElgamalScheme, mode?: AesMode, algorithm?: Algorithm }
  ): Promise<Uint8Array> {
    let { scheme, mode, algorithm } = opts;
    switch (scheme) {
      case ElgamalSchemes.IES:
        mode = mode || AesModes.DEFAULT;
        algorithm = algorithm || Algorithms.DEFAULT;
        return elgamal[ElgamalSchemes.IES](this.ctx, mode, algorithm).decrypt(
          ciphertext, this.secret,
        );
      case ElgamalSchemes.KEM:
        mode = mode || AesModes.DEFAULT;
        return elgamal[ElgamalSchemes.KEM](this.ctx, mode).decrypt(
          ciphertext, this.secret,
        );
      case ElgamalSchemes.PLAIN:
        return elgamal[ElgamalSchemes.PLAIN](this.ctx).decrypt(
          ciphertext, this.secret
        );
    }
  }

  async verifyEncryption(
    ciphertext: ElgamalCiphertext<P>,
    proof: SigmaProof<P>,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
  ): Promise<boolean> {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? opts.nonce : undefined;
    const verified = await dlog(ctx, algorithm).verify({ u: ctx.generator, v: ciphertext.beta }, proof, nonce);
    if (!verified) throw new Error(Messages.INVALID_ENCRYPTION_PROOF);
    return verified;
  }

  async proveDecryptor(
    ciphertext: ElgamalCiphertext<P>,
    decryptor: P,
    opts?: { algorithm?: Algorithm, nonce?: Uint8Array }
  ): Promise<SigmaProof<P>> {
    const { ctx, secret: secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const proof = await ddh(ctx, algorithm).prove(secret, { u: ciphertext.beta, v: pub, w: decryptor }, nonce);
    return proof;
  }

  async generateDecryptor(
    ciphertext: ElgamalCiphertext<P>,
    opts?: { noProof?: boolean, algorithm?: Algorithm },
  ): Promise<{ decryptor: P, proof?: SigmaProof<P> }> {
    const { ctx, secret: secret } = this;
    const decryptor = await ctx.operate(secret, ciphertext.beta);
    const noProof = opts ? opts.noProof : false;
    if (noProof) return { decryptor };
    const proof = await this.proveDecryptor(ciphertext, decryptor, opts);
    return { decryptor, proof };
  }
}


export interface SerializedPrivateShare extends SerializedPrivateKey {
  index: number;
}

export class PrivateShare<P extends Point> extends PrivateKey<P> implements BaseShare<bigint>{
  value: bigint;
  index: number;

  constructor(ctx: Group<P>, secret: bigint, index: number) {
    super(ctx, leInt2Buff(secret));
    this.value = this.secret;
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
    const pub = await ctx.operate(this.secret, ctx.generator);
    return new PublicShare(ctx, pub, index);
  }

  async verifyFeldmann(commitments: P[]): Promise<boolean> {
    const { ctx, value, index } = this;
    const secretShare = new SecretShare(value, index);
    const verified = await shamir(ctx).verifyFeldmann(secretShare, commitments);
    if (!verified) throw new Error('Invalid share');
    return verified;
  }

  async verifyPedersen(binding: bigint, pub: P, commitments: P[]): Promise<boolean> {
    const { ctx, value, index } = this;
    const secretShare = new SecretShare(value, index);
    const verified = await shamir(ctx).verifyPedersen(secretShare, binding, pub, commitments);
    if (!verified) throw new Error('Invalid share');
    return verified;
  }

  async generatePartialDecryptor(
    ciphertext: ElgamalCiphertext<P>,
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
