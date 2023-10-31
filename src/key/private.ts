import { Group, Point } from '../backend/abstract';
import { Ciphertext } from '../elgamal/core';
import { DlogProof } from '../sigma';
import { PublicKey } from './public';
import { Label } from '../types';
import { Messages } from './enums';

const backend = require('../backend');
const sigma = require('../sigma');
const elgamal = require('../elgamal');


export type SerializedPrivateKey = {
  value: bigint;
  system: Label;
}


export class PrivateKey<P extends Point> {
  ctx: Group<P>;
  secret: bigint;

  constructor(ctx: Group<P>, scalar: bigint) {
    this.ctx = ctx;
    this.secret = scalar;
  }

  serialize = (): SerializedPrivateKey => {
    const { ctx, secret } = this;
    return { value: secret, system: ctx.label };
  }

  async isEqual<Q extends Point>(other: PrivateKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.isEqual(other.ctx)) &&
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
    await ctx.assertValid(pub.point);
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
}
