import { Group, Point } from '../backend/abstract';
import { ErrorMessages } from '../errors';
import { initGroup } from '../backend';
import { Ciphertext } from '../elgamal';
import { leInt2Buff } from '../crypto/bitwise';
import { NizkProof } from '../nizk';
import { Signature } from '../signer';
import { Algorithms, AesModes, ElgamalSchemes, SignatureSchemes } from '../enums';
import { Algorithm, AesMode, ElgamalScheme, SignatureScheme, System } from '../types';

import elgamal from '../elgamal';
import nizk from '../nizk';
import signer from '../signer';


/** Byte "canonical" representation of a nested structure with string keys and
 * uint8 arrays as leaf values. Used in making structures of the above type
 * amenable to cryptographic operations (e.g., signing ciphertexts). Equivalent
 * to the following procedure:
 * 1. Sort keys recursively
 * 2. Encode leaf values as base64
 * 3. Dump with double quotes, no newlines and zero indentation
 * 4. Return bytes of dumped string
 */
const toCanonical = (obj: Object): Uint8Array => Buffer.from(JSON.stringify(
  obj, (key: string, value: any) => value instanceof Uint8Array ?
    Buffer.from(value).toString('base64') :
    Object.keys(value).sort().reduce(
      (sorted: any, key: any) => {
        sorted[key] = value[key];
        return sorted
      }, {}
    )
  )
)

/** Recovers the original structure from its "canonical" byte representation */
const fromCanonical = (repr: Uint8Array) => JSON.parse(
  Buffer.from(repr).toString(),
  (key: string, value: Object | string) =>
    typeof value === 'string' ?
    Uint8Array.from(Buffer.from(value, 'base64')) :
    value
)


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
    const { ctx: { operate, generator } } = this;
    const pubPoint = await operate(this.secret, generator);
    return new PublicKey(this.ctx, pubPoint.toBytes());
  }

  async diffieHellman(publicKey: PublicKey<P>): Promise<P> {
    const { ctx } = this;
    const pubPoint = publicKey.toPoint();
    await ctx.validatePoint(pubPoint);
    return ctx.operate(this.secret, pubPoint);
  }

  async sign(
    message: Uint8Array,
    opts: {
      scheme: SignatureScheme,
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<Signature> {
    let { scheme, algorithm, nonce } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    const signature = await signer(this.ctx, scheme, algorithm).signBytes(
      this.secret, message, nonce
    );
    return signature;
  }

  async proveIdentity(
    opts?: {
      nonce?: Uint8Array
      algorithm?: Algorithm,
    }): Promise<NizkProof> {
    const { ctx, secret: secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    return nizk(ctx, algorithm).proveDlog(secret, { u: ctx.generator, v: pub }, nonce);
  }

  async decrypt(
    ciphertext: Ciphertext,
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
    ciphertext: Ciphertext,
    decryptor: Uint8Array,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    }
  ): Promise<NizkProof> {
    const { ctx, secret } = this;
    const pub = await ctx.operate(secret, ctx.generator);
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    return nizk(ctx, algorithm).proveDDH(
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
    ciphertext: Ciphertext,
    opts?: { algorithm?: Algorithm },
  ): Promise<{
    decryptor: Uint8Array,
    proof: NizkProof
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

  async signEncrypt<Q extends Point>(
    message: Uint8Array,
    receiverPublic: PublicKey<Q>,
    opts: {
      encScheme: ElgamalSchemes.IES | ElgamalSchemes.KEM,
      sigScheme: SignatureScheme,
      algorithm?: Algorithm,
      mode?: AesMode,
      nonce?: Uint8Array,
    },
  ): Promise<{
    ciphertext: Ciphertext,
    signature: Signature,
  }> {
    const receiver = receiverPublic.bytes;
    const { encScheme, sigScheme, algorithm, mode, nonce } = opts;
    const _signer = signer(this.ctx, sigScheme, algorithm || Algorithms.DEFAULT);
    const _cipher = elgamal(
      this.ctx, encScheme, algorithm || Algorithms.DEFAULT, mode || AesModes.DEFAULT
    );
    const innerSignature = await _signer.signBytes(this.secret, message, nonce);
    const { ciphertext } = await _cipher.encrypt(
      toCanonical({ message, innerSignature }), receiver
    )
    const signature = await _signer.signBytes(
      this.secret, toCanonical({ ciphertext, receiver }), nonce
    )
    return { ciphertext, signature };
  }

  async verifyDecrypt<Q extends Point>(
    ciphertext: Ciphertext,
    signature: Signature,
    senderPublic: PublicKey<Q>,
    opts: {
      encScheme: ElgamalSchemes.IES | ElgamalSchemes.KEM,
      sigScheme: SignatureScheme,
      algorithm?: Algorithm,
      mode?: AesMode,
      nonce?: Uint8Array,
    },
  ): Promise<Uint8Array> {
    const receiver = (await this.publicKey()).bytes;  // TODO
    const { encScheme, sigScheme, algorithm, mode, nonce } = opts;
    const _signer = signer(this.ctx, sigScheme, algorithm || Algorithms.DEFAULT);
    const _cipher = elgamal(
      this.ctx, encScheme, algorithm || Algorithms.DEFAULT, mode || AesModes.DEFAULT
    );
    const outerVerified = await _signer.verifyBytes(
      senderPublic.bytes, toCanonical({ ciphertext, receiver }), signature, nonce
    );
    if (!outerVerified) throw new Error(ErrorMessages.INVALID_SIGNATURE); // TODO: Handle
    const plaintext = await _cipher.decrypt(ciphertext, this.secret);     // TODO: Handle
    const { message, innerSignature } = fromCanonical(plaintext);
    const innerVerified = await _signer.verifyBytes(
      senderPublic.bytes, message, innerSignature, nonce
    );
    if (!innerVerified) throw new Error(ErrorMessages.INVALID_SIGNATURE); // TODO: Handle
    return message;
  }
}


class PublicKey<P extends Point> {
  ctx: Group<P>;
  bytes: Uint8Array;

  constructor(ctx: Group<P>, bytes: Uint8Array) {
    this.ctx = ctx;
    // TODO: point validation
    this.bytes = bytes;
  }

  toPoint(): P {
    return this.ctx.unpack(this.bytes);
  }

  static async fromPoint(ctx: Group<Point>, pubPoint: Point): Promise<PublicKey<Point>> {
    await ctx.validatePoint(pubPoint);
    return new PublicKey(ctx, pubPoint.toBytes());
  }

  async equals<Q extends Point>(other: PublicKey<Q>): Promise<boolean> {
    // TODO: Secure constant time bytes comparison
    const isEqualBuffer = (a: Uint8Array, b: Uint8Array) => {
      if (a.length != b.length) return false;
      for (let i = 0; i < a.length; i++)
        if (a[i] != b[i]) return false;
      return true;
    }
    return (
      (await this.ctx.equals(other.ctx)) &&
      isEqualBuffer(this.bytes, other.bytes)
    );
  }

  async verifySignature(
    message: Uint8Array,
    signature: Signature,
    opts: {
      scheme: SignatureScheme,
      algorithm?: Algorithm
      nonce?: Uint8Array,
    },
  ): Promise<boolean> {
    let { scheme, algorithm, nonce } = opts;
    algorithm = algorithm || Algorithms.DEFAULT;
    const verified = await signer(this.ctx, scheme, algorithm).verifyBytes(
      this.bytes, message, signature, nonce
    );
    if (!verified) throw new Error(ErrorMessages.INVALID_SIGNATURE);
    return verified;
  }

  async verifyIdentity(
    proof: NizkProof,
    opts?: {
      nonce?: Uint8Array,
      algorithm?: Algorithm,
    },
  ): Promise<boolean> {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce || undefined) : undefined;
    const pub = ctx.unpack(this.bytes);
    const verified = await nizk(ctx, algorithm).verifyDlog(
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
    ciphertext: Ciphertext,
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
        v: ctx.unpack(ciphertext.beta),
      },
      nonce
    );
  }

  async verifyDecryptor(
    ciphertext: Ciphertext,
    decryptor: Uint8Array,
    proof: NizkProof,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
      raiseOnInvalid?: boolean
    }
  ): Promise<boolean> {
    const { ctx } = this;
    const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) :
      Algorithms.DEFAULT;
    const nonce = opts ? (opts.nonce) : undefined;
    const verified = await nizk(ctx, algorithm).verifyDDH(
      {
        u: ctx.unpack(ciphertext.beta),
        v: ctx.unpack(this.bytes),
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
