import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { DlogProof } from '../sigma';
import { PublicKey } from './public';
import { Label } from '../types';
import { Messages } from './enums';
import { leInt2Buff } from '../utils';

const backend = require('../backend');
const sigma = require('../sigma');
const elgamal = require('../elgamal');


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
      (this.secret == other.secret)
    );
  }

  async publicPoint(): Promise<P> {
    const { ctx, secret } = this;
    return ctx.operate(secret, ctx.generator);
  }

  async publicKey(): Promise<PublicKey<P>> {
    const { ctx, secret } = this;
    const point = await ctx.operate(secret, ctx.generator);
    return new PublicKey(ctx, point);
  }

  async diffieHellman(pub: PublicKey<P>): Promise<P> {
    const { ctx, secret } = this;
    await ctx.validatePoint(pub.point);
    return ctx.operate(secret, pub.point);
  }

  async proveIdentity(opts?: { algorithm?: Algorithm }): Promise<DlogProof<P>> {
    const { ctx, secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    return sigma.proveDlog(ctx, secret, ctx.generator, pub, opts);
  }

  async decrypt(ciphertext: Ciphertext<P>): Promise<P> {
    return elgamal.decrypt(this.ctx, ciphertext, { secret: this.secret });
  }

  async verifyEncryption(ciphertext: Ciphertext<P>, proof: DlogProof<P>): Promise<boolean> {
    const verified = await elgamal.verifyEncryption(this.ctx, ciphertext, proof);
    if (!verified) throw new Error(Messages.INVALID_ENCRYPTION_PROOF);
    return verified;
  }

  async proveDecryptor(
    ciphertext: Ciphertext<P>,
    decryptor: P,
    opts?: { algorithm?: Algorithm }
  ): Promise<DlogProof<P>> {
    const { ctx, secret } = this;
    return elgamal.proveDecryptor(ctx, ciphertext, secret, decryptor, opts);
  }
}
