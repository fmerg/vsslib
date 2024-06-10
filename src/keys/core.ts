import { Group, Point } from '../backend/abstract';
import {
  ShamirError,
  InvalidSignature,
  InvalidSecret,
  InvalidDecryptor,
  InvalidEncryptionProof,
} from '../errors';
import { initGroup } from '../backend';
import { Ciphertext } from '../elgamal';
import { leInt2Buff } from '../arith';
import { NizkProof } from '../nizk';
import { Signature } from '../signer';
import { Algorithms, BlockModes, ElgamalSchemes, SignatureSchemes } from '../enums';
import { Algorithm, BlockMode, ElgamalScheme, SignatureScheme } from '../types';
import { toCanonical, fromCanonical, ctEqualBuffer } from '../common';
import { distributeSecret, ShamirSharing } from '../shamir';

import elgamal from '../elgamal';
import nizk from '../nizk';
import signer from '../signer';


export class PrivateKey<P extends Point> {
  ctx: Group<P>;
  bytes: Uint8Array;

  constructor(ctx: Group<P>, bytes: Uint8Array) {
    this.ctx = ctx;
    this.bytes = bytes;
  }

  async equals<Q extends Point>(other: PrivateKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.equals(other.ctx)) &&
        (this.asScalar() == other.asScalar())
    );
  }

  asScalar = (): bigint => this.ctx.leBuff2Scalar(this.bytes);

  getPublic = async (): Promise<P> => {
    const { exp, generator: g } = this.ctx;
    return exp(g, this.asScalar());
  }

  getPublicBytes = async (): Promise<Uint8Array> => {
    return (await this.getPublic()).toBytes();
  }

  getPublicKey = async (): Promise<PublicKey<P>> => new PublicKey(
    this.ctx, await this.getPublicBytes()
  );

  proveSecret = async (opts?: { nonce?: Uint8Array, algorithm?: Algorithm }): Promise<
    NizkProof
  > => {
    const { generator: g } = this.ctx
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    return nizk(this.ctx, algorithm).proveDlog(
      this.asScalar(),
      {
        u: g,
        v: await this.getPublic(),
      },
      nonce
    );
  }

  generateSharing = async (nrShares: number, threshold: number): Promise<ShamirSharing<P>> => {
    return distributeSecret(this.ctx, nrShares, threshold, this.bytes);
  }

  signMessage = async (
    message: Uint8Array,
    opts: {
      scheme: SignatureScheme,
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<Signature> => {
    let { scheme, algorithm, nonce } = opts;
    return signer(this.ctx, scheme, algorithm || Algorithms.DEFAULT).signBytes(
      this.asScalar(), message, nonce
    );
  }

  decrypt = async (
    ciphertext: Ciphertext,
    opts: {
      scheme: ElgamalScheme,
      algorithm?: Algorithm
      mode?: BlockMode,
    }
  ): Promise<Uint8Array> => {
    let { scheme, mode, algorithm } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    mode = mode || BlockModes.DEFAULT;
    return elgamal(this.ctx, scheme, algorithm, mode).decrypt(
      ciphertext,
      this.asScalar()
    );
  }

  verifyEncryption = async (
    ciphertext: Ciphertext,
    proof: NizkProof,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    },
  ): Promise<boolean> => {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? opts.nonce : undefined;
    const verified = await nizk(ctx, algorithm).verifyDlog(
      {
        u: ctx.generator,
        v: await ctx.unpackValid(ciphertext.beta),
      },
      proof,
      nonce,
    );
    if (!verified) throw new InvalidEncryptionProof(
      `Invalid encryption`  // TODO
    );
    return verified;
  }

  proveDecryptor = async (
    ciphertext: Ciphertext,
    decryptor: Uint8Array,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<NizkProof> => {
    const ctx = this.ctx;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    return nizk(ctx, algorithm).proveDDH(
      this.asScalar(),
      {
        u: await ctx.unpackValid(ciphertext.beta),
        v: await this.getPublic(),
        w: await ctx.unpackValid(decryptor),
      },
      nonce
    );
  }

  computeDecryptor = async (
    ciphertext: Ciphertext, opts?: { algorithm?: Algorithm }
  ): Promise<{
    decryptor: Uint8Array,
    proof: NizkProof
  }> => {
    const beta = await this.ctx.unpackValid(ciphertext.beta);
    const d = await this.ctx.exp(beta, this.asScalar());
    const decryptor = d.toBytes();
    const proof = await this.proveDecryptor(
      ciphertext,
      decryptor,
      opts
    );
    return { decryptor, proof };
  }

  async signEncrypt<Q extends Point>(
    message: Uint8Array,
    receiverPublic: PublicKey<Q>,
    opts: {
      encScheme: ElgamalSchemes.DHIES | ElgamalSchemes.HYBRID,
      sigScheme: SignatureScheme,
      algorithm?: Algorithm,
      mode?: BlockMode,
      nonce?: Uint8Array,
    },
  ): Promise<{
    ciphertext: Ciphertext,
    signature: Signature,
  }> {
    let { encScheme, sigScheme, algorithm, mode, nonce } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    mode = mode || BlockModes.DEFAULT;
    const _signer = signer(this.ctx, sigScheme, algorithm);
    const _cipher = elgamal(this.ctx, encScheme, algorithm, mode);
    const innerSignature = await _signer.signBytes(this.asScalar(), message, nonce);
    const receiver = receiverPublic.asBytes();
    const { ciphertext } = await _cipher.encrypt(
      toCanonical({ message, innerSignature }), receiver
    )
    const signature = await _signer.signBytes(
      this.asScalar(), toCanonical({ ciphertext, receiver }), nonce
    )
    return { ciphertext, signature };
  }

  async verifyDecrypt<Q extends Point>(
    ciphertext: Ciphertext,
    signature: Signature,
    senderPublic: PublicKey<Q>,
    opts: {
      encScheme: ElgamalSchemes.DHIES | ElgamalSchemes.HYBRID,
      sigScheme: SignatureScheme,
      algorithm?: Algorithm,
      mode?: BlockMode,
      nonce?: Uint8Array,
    },
  ): Promise<{ message: Uint8Array, innerSignature: Signature }> {
    let { encScheme, sigScheme, algorithm, mode, nonce } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    mode = mode || BlockModes.DEFAULT;
    const _signer = signer(this.ctx, sigScheme, algorithm);
    const _cipher = elgamal(this.ctx, encScheme, algorithm, mode);
    const receiver = await this.getPublicBytes();
    const outerVerified = await _signer.verifyBytes(
      senderPublic.asBytes(), toCanonical({ ciphertext, receiver }), signature, nonce
    );
    if (!outerVerified) throw new InvalidSignature(
      `Invalid signature` // TODO
    );
    const plaintext = await _cipher.decrypt(ciphertext, this.asScalar());
    const { message, innerSignature } = fromCanonical(plaintext);
    const innerVerified = await _signer.verifyBytes(
      senderPublic.asBytes(), message, innerSignature, nonce
    );
    if (!innerVerified) throw new InvalidSignature(
      `Invalid signature` // TODO
    );
    return { message, innerSignature };
  }
}


export class PublicKey<P extends Point> {
  ctx: Group<P>;
  bytes: Uint8Array;

  constructor(ctx: Group<P>, bytes: Uint8Array) {
    this.ctx = ctx;
    this.bytes = bytes;
  }

  asPoint = async (): Promise<P> => this.ctx.unpackValid(this.bytes);
  asBytes = (): Uint8Array => this.bytes;

  async equals<Q extends Point>(other: PublicKey<Q>): Promise<boolean> {
    return (
      (await this.ctx.equals(other.ctx)) &&
        ctEqualBuffer(this.bytes, other.bytes)
    );
  }

  verifySecret = async (
    proof: NizkProof,
    opts?: {
      nonce?: Uint8Array,
      algorithm?: Algorithm,
    },
  ): Promise<boolean> => {
    const { generator: g } = this.ctx;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const verified = await nizk(this.ctx, algorithm).verifyDlog(
      {
        u: g,
        v: await this.asPoint(),
      },
      proof,
      nonce,
    );
    if (!verified) throw new InvalidSecret(
      `Invalid secret` // TODO
    );
    return verified;
  }

  verifySignature = async (
    message: Uint8Array,
    signature: Signature,
    opts: {
      scheme: SignatureScheme,
      algorithm?: Algorithm
      nonce?: Uint8Array,
    },
  ): Promise<boolean> => {
    let { scheme, algorithm, nonce } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    const verified = await signer(this.ctx, scheme, algorithm).verifyBytes(
      this.bytes, message, signature, nonce
    );
    if (!verified) throw new InvalidSignature(
      `Invalid signature` // TODO
    );
    return verified;
  }

  encrypt = async (
    message: Uint8Array,
    opts: {
      scheme: ElgamalScheme,
      algorithm?: Algorithm
      mode?: BlockMode,
    }
  ): Promise<{
    ciphertext: Ciphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    let { scheme, mode, algorithm } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    mode = mode || BlockModes.DEFAULT;
    return elgamal(this.ctx, scheme, algorithm, mode).encrypt(
      message, this.bytes
    );
  }

  proveEncryption = async (
    ciphertext: Ciphertext,
    randomness: Uint8Array,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<NizkProof> => {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    return nizk(ctx, algorithm).proveDlog(
      ctx.leBuff2Scalar(randomness),
      {
        u: ctx.generator,
        v: await ctx.unpackValid(ciphertext.beta),
      },
      nonce
    );
  }

  verifyDecryptor = async (
    ciphertext: Ciphertext,
    decryptor: Uint8Array,
    proof: NizkProof,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<boolean> => {
    const { unpackValid } = this.ctx;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const verified = await nizk(this.ctx, algorithm).verifyDDH(
      {
        u: await unpackValid(ciphertext.beta),
        v: await unpackValid(this.bytes),
        w: await unpackValid(decryptor),
      },
      proof,
      nonce,
    );
    if (!verified) throw new InvalidDecryptor(
      `Invalid decryptor`   // TODO
    );
    return verified;
  }
}
