import { Group, Point } from './backend/abstract';
import { ElgamalCiphertext } from './crypto/elgamal';
import { NizkProof } from './nizk';
import { BaseShare, BaseSharing } from './base';
import { ErrorMessages } from './errors';
import { SecretShare } from './shamir';
import { leInt2Buff } from './crypto/bitwise';
import { PrivateKey, PublicKey } from './keys';
import { Algorithm, AesMode, ElgamalScheme } from './types';
import { Algorithms, AesModes, ElgamalSchemes, SignatureSchemes } from './enums';

const shamir = require('./shamir');


export class PrivateShare<P extends Point> extends PrivateKey<P> implements BaseShare<bigint>{
  value: bigint;
  index: number;

  constructor(ctx: Group<P>, secret: bigint, index: number) {
    super(ctx, leInt2Buff(secret));
    this.value = this.secret;
    this.index = index;
  }

  async publicShare(): Promise<PublicShare<P>> {
    const { ctx, index } = this;
    const pub = await ctx.operate(this.secret, ctx.generator);
    return new PublicShare(ctx, pub, index);
  }

  async verifyFeldmann(commitments: P[]): Promise<boolean> {
    const { ctx, value, index } = this;
    const secretShare = new SecretShare(value, index);
    const verified = await shamir.verifyFeldmann(ctx, secretShare, commitments);
    if (!verified) throw new Error(ErrorMessages.INVALID_SHARE);
    return verified;
  }

  async verifyPedersen(binding: bigint, pub: P, commitments: P[]): Promise<boolean> {
    const { ctx, value, index } = this;
    const secretShare = new SecretShare(value, index);
    const verified = await shamir.verifyPedersen(ctx, secretShare, binding, pub, commitments);
    if (!verified) throw new Error(ErrorMessages.INVALID_SHARE);
    return verified;
  }

  async generatePartialDecryptor(
    ciphertext: ElgamalCiphertext<P>, opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
  ): Promise<PartialDecryptor<P>> {
    const { decryptor, proof } = await this.generateDecryptor(ciphertext, opts);
    return { value: decryptor, index: this.index, proof };
  }
};


export class PublicShare<P extends Point> extends PublicKey<P> {
  value: P;
  index: number;

  constructor(ctx: Group<P>, pub: P, index: number) {
    super(ctx, pub);
    this.value = pub;
    this.index = index;
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
    if (!verified && raiseOnInvalid) throw new Error(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
    return verified;
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


export class PartialDecryptor<P extends Point> implements BaseShare<P> {
  value: P;
  index: number;
  proof: NizkProof<P>;

  constructor(value: P, index: number, proof: NizkProof<P>) {
    this.value = value;
    this.index = index;
    this.proof = proof;
  }
};
