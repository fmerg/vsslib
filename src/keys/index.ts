import { Group, Point } from '../backend/abstract';
import { ErrorMessages } from '../errors';
import { initGroup } from '../backend';
import { ElgamalCiphertext } from '../crypto/elgamal';
import { leInt2Buff } from '../crypto/bitwise';
import { dlog, ddh, NizkProof } from '../nizk';
import { Signature } from '../crypto/signer/base';
import { SchnorrSignature } from '../crypto/signer/schnorr';
import { Algorithms, AesModes, ElgamalSchemes, SignatureSchemes } from '../enums';
import { Algorithm, AesMode, ElgamalScheme, System } from '../types';

import signer from '../crypto/signer';
import elgamal from '../crypto/elgamal';


class PrivateKey<P extends Point> {
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

  async proveIdentity(opts?: { algorithm?: Algorithm, nonce?: Uint8Array }): Promise<NizkProof<P>> {
    const { ctx, secret: secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    return dlog(ctx, algorithm).prove(secret, { u: ctx.generator, v: pub }, nonce);
  }

  async decrypt(
    ciphertext: ElgamalCiphertext,
    opts: {
      scheme: ElgamalScheme,
      algorithm?: Algorithm
      mode?: AesMode,
    }
  ): Promise<Uint8Array> {
    let { scheme, mode, algorithm } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    mode = mode || AesModes.DEFAULT;
    return elgamal(this.ctx, scheme, algorithm, mode).decrypt(
      ciphertext, this.secret
    );
  }

  verifyEncryption = async (
    ciphertext: ElgamalCiphertext,
    proof: NizkProof<P>,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    },
  ): Promise<boolean> => {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? opts.nonce : undefined;
    const verified = await dlog(ctx, algorithm).verify(
      {
        u: ctx.generator,
        v: ctx.unpack(ciphertext.beta),
      },
      proof,
      nonce,
    );
    if (!verified) throw new Error(
      ErrorMessages.INVALID_ENCRYPTION
    );
    return verified;
  }

  async proveDecryptor(
    ciphertext: ElgamalCiphertext,
    decryptor: Uint8Array,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<NizkProof<P>> {
    const { ctx, secret: secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    return ddh(ctx, algorithm).prove(
      secret,
      {
        u: ctx.unpack(ciphertext.beta),
        v: pub,
        w: ctx.unpack(decryptor),
      },
      nonce
    );
  }

  async generateDecryptor(
    ciphertext: ElgamalCiphertext,
    opts?: { algorithm?: Algorithm },
  ): Promise<{
    decryptor: Uint8Array,
    proof: NizkProof<P>
  }> {
    const { ctx, secret } = this;
    const decryptorPoint = await ctx.operate(
      secret,
      ctx.unpack(ciphertext.beta),
    );
    const decryptor = decryptorPoint.toBytes();
    const proof = await this.proveDecryptor(
      ciphertext,
      decryptor,
      opts
    );
    return { decryptor, proof };
  }
}


class PublicKey<P extends Point> {
  ctx: Group<P>;
  bytes: Uint8Array;
  pub: P;

  constructor(ctx: Group<P>, pub: P) {
    this.ctx = ctx;
    this.bytes = pub.toBytes();
    this.pub = pub;
  }

  static async fromPoint(ctx: Group<Point>, pub: Point): Promise<PublicKey<Point>> {
    await ctx.validatePoint(pub);
    return new PublicKey(ctx, pub);
  }

  async equals<Q extends Point>(other: PublicKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.equals(other.ctx)) &&
      // TODO: Constant time bytes comparison
      (await this.pub.equals(other.pub))
    );
  }

  async verifySignature(
    message: Uint8Array,
    signature: Signature<P>,
    opts: { nonce?: Uint8Array, algorithm?: Algorithm },
  ): Promise<boolean> {
    const { ctx, pub } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const verified = await signer(ctx, SignatureSchemes.SCHNORR, algorithm).verifyBytes(
      pub, message, signature as SchnorrSignature<P>, nonce
    );
    if (!verified) throw new Error(ErrorMessages.INVALID_SIGNATURE);
    return verified;
  }

  async verifyIdentity(proof: NizkProof<P>, nonce?: Uint8Array): Promise<boolean> {
    const { ctx, pub } = this;
    const verified = await dlog(ctx, Algorithms.DEFAULT).verify(
      { u: ctx.generator, v: pub }, proof, nonce
    );
    if (!verified) throw new Error(ErrorMessages.INVALID_SECRET);
    return verified;
  }

  async encrypt(
    message: Uint8Array,
    opts: {
      scheme: ElgamalScheme,
      algorithm?: Algorithm
      mode?: AesMode,
    }
  ): Promise<{
    ciphertext: ElgamalCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> {
    let { scheme, mode, algorithm } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    mode = mode || AesModes.DEFAULT;
    return elgamal(this.ctx, scheme, algorithm, mode).encrypt(
      message, this.bytes
    );
  }

  proveEncryption = async (
    ciphertext: ElgamalCiphertext,
    randomness: Uint8Array,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<NizkProof<P>> => {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    return dlog(ctx, algorithm).prove(
      ctx.leBuff2Scalar(randomness),
      {
        u: ctx.generator,
        v: ctx.unpack(ciphertext.beta),
      },
      nonce
    );
  }

  async verifyDecryptor(
    ciphertext: ElgamalCiphertext,
    decryptor: Uint8Array,
    proof: NizkProof<P>,
    opts?: { nonce?: Uint8Array, raiseOnInvalid?: boolean }
  ): Promise<boolean> {
    const { ctx, pub } = this;
    const nonce = opts ? (opts.nonce) : undefined;
    const verified = await ddh(ctx, Algorithms.DEFAULT).verify(
      {
        u: ctx.unpack(ciphertext.beta),
        v: pub,
        w: ctx.unpack(decryptor)
      },
      proof,
      nonce
    );
    const raiseOnInvalid = opts ?
      (opts.raiseOnInvalid === undefined ? true : opts.raiseOnInvalid) :
      true;
    if (!verified && raiseOnInvalid) throw new Error(ErrorMessages.INVALID_DECRYPTOR);
    return verified;
  }
}


type KeyPair<P extends Point> = {
  privateKey: PrivateKey<P>, publicKey: PublicKey<P>, ctx: Group<P>
};

async function generateKey(system: System): Promise<KeyPair<Point>> {
  const ctx = initGroup(system);
  const privateKey = new PrivateKey(ctx, await ctx.randomBytes());
  const publicKey = await privateKey.publicKey();
  return { privateKey, publicKey, ctx };
}


export {
  generateKey,
  PrivateKey,
  PublicKey,
}
