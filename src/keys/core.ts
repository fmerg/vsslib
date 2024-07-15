import { Group, Point } from 'vsslib/backend';
import { Ciphertext } from 'vsslib/elgamal';
import { NizkProof } from 'vsslib/nizk';
import { Signature } from 'vsslib/signer';
import { randomSecret, unpackScalar, unpackPoint, extractPublic, isEqualPublic } from 'vsslib/secrets';
import { distributeSecret, ShamirSharing } from 'vsslib/dealer';
import { InvalidDecryptor, InvalidEncryption, InvalidSecret, InvalidSignature } from 'vsslib/errors';
import { Algorithms, BlockModes, ElgamalSchemes } from 'vsslib/enums';
import { Algorithm, BlockMode, ElgamalScheme, SignatureScheme } from 'vsslib/types';
import { toCanonical, fromCanonical } from 'vsslib/common';

import elgamal from 'vsslib/elgamal';
import nizk from 'vsslib/nizk';
import signer from 'vsslib/signer';


export class PrivateKey<P extends Point> {
  ctx: Group<P>;
  secret: Uint8Array;

  constructor(ctx: Group<P>, secret: Uint8Array) {
    this.ctx = ctx;
    this.secret = secret;
  }

  asBytes = (): Uint8Array => this.secret;

  getPublicKey = async (): Promise<PublicKey<P>> => new PublicKey(
    this.ctx, await extractPublic(this.ctx, this.secret)
  );

  proveSecret = async (opts?: { nonce?: Uint8Array, algorithm?: Algorithm }): Promise<
    NizkProof
  > => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const g = this.ctx.generator;
    const x = await unpackScalar(this.ctx, this.secret);
    const y = await this.ctx.exp(g, x);
    return nizk(this.ctx, algorithm).proveDlog(
      x,
      {
        u: g,
        v: y,
      },
      nonce
    );
  }

  generateSharing = async (nrShares: number, threshold: number): Promise<ShamirSharing<P>> => {
    const { sharing } = await distributeSecret(
      this.ctx, nrShares, threshold, this.secret
    );
    return sharing;
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
      this.secret, message, nonce
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
      ciphertext, this.secret
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
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? opts.nonce : undefined;
    const g = this.ctx.generator;
    const b = await unpackPoint(this.ctx, ciphertext.beta);
    const isValid = await nizk(this.ctx, algorithm).verifyDlog(
      {
        u: g,
        v: b,
      },
      proof,
      nonce,
    );
    if (!isValid) throw new InvalidEncryption(
      `Invalid encryption`  // TODO: More informative message?
    );
    return isValid;
  }

  verifyDecrypt = async (
    ciphertext: Ciphertext,
    proof: NizkProof,
    opts: {
      scheme: ElgamalScheme,
      encAlgorithm?: Algorithm,
      mode?: BlockMode,
      verAlgorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<{ plaintext: Uint8Array, proof: NizkProof }> => {
    const { scheme, encAlgorithm, mode, verAlgorithm, nonce } = opts;
    await this.verifyEncryption(ciphertext, proof, {
      algorithm: verAlgorithm, nonce
    });
    const plaintext = await this.decrypt(ciphertext, {
      scheme, algorithm: encAlgorithm, mode
    });
    return { plaintext, proof };
  }

  proveDecryptor = async (
    ciphertext: Ciphertext,
    decryptor: Uint8Array,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<NizkProof> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const g = this.ctx.generator;
    const x = await unpackScalar(this.ctx, this.secret);
    const y = await this.ctx.exp(g, x);
    const b = await unpackPoint(this.ctx, ciphertext.beta);
    const d = await unpackPoint(this.ctx, decryptor);
    return nizk(this.ctx, algorithm).proveDDH(
      x,
      {
        u: b,
        v: y,
        w: d,
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
    const b = await unpackPoint(this.ctx, ciphertext.beta);
    const x = await unpackScalar(this.ctx, this.secret);
    const decryptor = (await this.ctx.exp(b, x)).toBytes();
    const proof = await this.proveDecryptor(
      ciphertext,
      decryptor,
      opts
    );
    return { decryptor, proof };
  }

  async sigEncrypt<Q extends Point>(
    message: Uint8Array,
    recipientPublic: PublicKey<Q>,
    opts: {
      encScheme: ElgamalSchemes.DHIES | ElgamalSchemes.HYBRID,
      sigScheme: SignatureScheme,
      algorithm?: Algorithm,
      mode?: BlockMode,
      nonce?: Uint8Array,
    },
  ): Promise<{ ciphertext: Ciphertext, signature: Signature }> {
    let { encScheme, sigScheme, algorithm, mode, nonce } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    mode = mode || BlockModes.DEFAULT;
    const _signer = signer(this.ctx, sigScheme, algorithm);
    const _cipher = elgamal(this.ctx, encScheme, algorithm, mode);
    const recipient = recipientPublic.asBytes();
    const { ciphertext } = await _cipher.encrypt(
      toCanonical({
        message,
        innerSignature: await _signer.signBytes(
          this.secret,
          message,
          nonce
        )
      }),
      recipient
    )
    const signature = await _signer.signBytes(
      this.secret, toCanonical({ ciphertext, recipient }), nonce
    )
    return { ciphertext, signature };
  }

  async sigDecrypt<Q extends Point>(
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
    const recipient = await extractPublic(this.ctx, this.secret);
    const isOuterValid = await _signer.verifyBytes(
      senderPublic.asBytes(),
      toCanonical({
        ciphertext,
        recipient
      }),
      signature,
      nonce
    );
    if (!isOuterValid) throw new InvalidSignature(
      `Invalid outer signature`
    );
    const plaintext = await _cipher.decrypt(ciphertext, this.secret);
    const { message, innerSignature } = fromCanonical(plaintext);
    const isInnerValid = await _signer.verifyBytes(
      senderPublic.asBytes(), message, innerSignature, nonce
    );
    if (!isInnerValid) throw new InvalidSignature(
      `Invalid inner signature`
    );
    return { message, innerSignature };
  }
}


export class PublicKey<P extends Point> {
  ctx: Group<P>;
  publicBytes: Uint8Array;

  constructor(ctx: Group<P>, publicBytes: Uint8Array) {
    this.ctx = ctx;
    this.publicBytes = publicBytes;
  }

  async equals(other: PublicKey<P>): Promise<boolean> {
     return isEqualPublic(this.ctx, this.publicBytes, other.publicBytes);
  }

  asBytes = (): Uint8Array => this.publicBytes;

  verifySecret = async (
    proof: NizkProof,
    opts?: {
      nonce?: Uint8Array,
      algorithm?: Algorithm,
    },
  ): Promise<boolean> => {
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const g = this.ctx.generator;
    const y = await unpackPoint(this.ctx, this.publicBytes);
    const isValid = await nizk(this.ctx, algorithm).verifyDlog(
      {
        u: g,
        v: y,
      },
      proof,
      nonce,
    );
    if (!isValid) throw new InvalidSecret(
      `Invalid Schnorr proof`
    );
    return isValid;
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
    const isValid = await signer(this.ctx, scheme, algorithm).verifyBytes(
      this.publicBytes, message, signature, nonce
    );
    if (!isValid) throw new InvalidSignature(
      `Invalid signature` // TODO: More informative message
    );
    return isValid;
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
      message, this.publicBytes
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
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const g = this.ctx.generator;
    const r = await unpackScalar(this.ctx, randomness);
    const b = await unpackPoint(this.ctx, ciphertext.beta);
    return nizk(this.ctx, algorithm).proveDlog(
      r,
      {
        u: g,
        v: b,
      },
      nonce
    );
  }

  encryptProve = async (
    message: Uint8Array,
    opts: {
      scheme: ElgamalScheme,
      encAlgorithm?: Algorithm,
      mode?: BlockMode,
      verAlgorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<{ ciphertext: Ciphertext, proof: NizkProof }> => {
    const { scheme, encAlgorithm, mode, verAlgorithm, nonce } = opts;
    const { ciphertext, randomness } = await this.encrypt(message, {
      scheme, algorithm: encAlgorithm, mode
    });
    const proof = await this.proveEncryption(ciphertext, randomness, {
      algorithm: verAlgorithm, nonce
    });
    return { ciphertext, proof };
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
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const b = await unpackPoint(this.ctx, ciphertext.beta);
    const y = await unpackPoint(this.ctx, this.publicBytes);
    const d = await unpackPoint(this.ctx, decryptor);
    const isValid = await nizk(this.ctx, algorithm).verifyDDH(
      {
        u: b,
        v: y,
        w: d,
      },
      proof,
      nonce,
    );
    if (!isValid) throw new InvalidDecryptor(
      `Invalid decryptor` // TODO: More informative message?
    );
    return isValid;
  }
}


export const generateKey = async <P extends Point>(ctx: Group<P>): Promise<
  { privateKey: PrivateKey<P>, publicKey: PublicKey<P> }
> => {
  const { secret } = await randomSecret(ctx);
  const privateKey = new PrivateKey(ctx, secret);
  const publicKey = await privateKey.getPublicKey();
  return { privateKey, publicKey };
}
