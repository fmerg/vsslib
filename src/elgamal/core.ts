import { Point, Group } from '../backend';
import { leInt2Buff } from '../arith';
import { Algorithms, BlockModes } from '../enums';
import { Algorithm, BlockMode } from '../types';
import { AesError, ElgamalError } from '../errors';

import { hash, hmac, aes } from '../crypto';

/** First component of a HYBRID-Elgamal ciphertext */
export type HybridAlpha = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  tag?: Uint8Array,
};

/** First component of a DHIES-Elgamal ciphertext **/
export type DhiesAlpha = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  mac: Uint8Array,
  tag?: Uint8Array,
}


/** Generic ElGamal functionality; abstracts away encapsulation details */
abstract class BaseCipher<P extends Point, A> {
  ctx: Group<P>;

  constructor(ctx: Group<P>) {
    this.ctx = ctx;
  }

  abstract encapsulate: (pub: P, randomness: bigint, message: Uint8Array) => Promise<{
    alpha: A,
    decryptor: P
  }>;
  abstract decapsulate: (alpha: A, decryptor: P) => Promise<Uint8Array>;

  async encrypt(message: Uint8Array, pub: P): Promise<{
    ciphertext: {
      alpha: A,
      beta: Uint8Array,
    },
    decryptor: Uint8Array,
    randomness: Uint8Array,
  }> {
    const { ctx: { generator, randomScalar, exp }, encapsulate } = this;
    const randomness = await randomScalar();
    const { alpha, decryptor } = await encapsulate(pub, randomness, message);
    const beta = await exp(generator, randomness);
    return {
      ciphertext: {
        alpha,
        beta: beta.toBytes(),
      },
      decryptor: decryptor.toBytes(),
      randomness: leInt2Buff(randomness)
    };
  }

  async decrypt(ciphertext: { alpha: A, beta: Uint8Array}, secret: bigint): Promise<Uint8Array> {
    const { alpha, beta: betaBytes} = ciphertext;
    let beta;
    try {
      beta = await this.ctx.unpackValid(betaBytes);
    } catch (err: any) {
      throw new ElgamalError(
        'Could not decrypt: ' + err.message // TODO
      );
    }
    const decryptor = await this.ctx.exp(beta, secret);
    try {
      return await this.decapsulate(alpha, decryptor);
    } catch (err: any) {
      throw new Error('Could not decrypt: ' + err.message);
    }
  }

  async decryptWithDecryptor(
    ciphertext: {
      alpha: A,
      beta: Uint8Array,
    },
    decryptor: Uint8Array
  ): Promise<Uint8Array> {
    try {
      return await this.decapsulate(
        ciphertext.alpha, await this.ctx.unpackValid(decryptor)
      );
    } catch (err: any) {
      throw new ElgamalError(
        'Could not decrypt: ' + err.message
      );
    }
  }

  async decryptWithRandomness(
    ciphertext: {
      alpha: A,
      beta: Uint8Array
    },
    pub: P,
    randomness: Uint8Array
  ): Promise<Uint8Array> {
    const decryptor = await this.ctx.exp(pub, this.ctx.leBuff2Scalar(randomness));
    try {
      return await this.decapsulate(ciphertext.alpha, decryptor);
    } catch (err: any) {
      throw new ElgamalError(
        'Could not decrypt: ' + err.message
      );
    }
  }
}


/** Plain Elgamal encryption, assuming messages to be valid byte representations
 * of group elements. This not CCA-secure; do *not* use it directly, unless you
 * know what you do. */
export class PlainCipher<P extends Point> extends BaseCipher<P, Uint8Array> {
  constructor(ctx: Group<P>) {
    super(ctx);
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{
    alpha: Uint8Array,
    decryptor: P
  }> => {
    let messageUnpacked;
    try {
      messageUnpacked = await this.ctx.unpackValid(message);
    } catch (err: any) {
      throw new ElgamalError(err.message);
    }
    const decryptor = await this.ctx.exp(pub, randomness);
    const alpha = await this.ctx.operate(decryptor, messageUnpacked);
    return { alpha: alpha.toBytes(), decryptor };
  }

  decapsulate = async (alpha: Uint8Array, decryptor: P): Promise<Uint8Array> => {
    let alphaUnpacked;
    try {
      alphaUnpacked = await this.ctx.unpackValid(alpha);
    } catch (err: any) {
      throw new ElgamalError(err.message);
    }
    const decryptorInverse = await this.ctx.invert(decryptor);
    const plaintext = await this.ctx.operate(alphaUnpacked, decryptorInverse);
    return plaintext.toBytes();
  }
}

/** HYBRID-Elgamal encryption (DH-based Key Encapsulation Mechanism) */
export class HybridCipher<P extends Point> extends BaseCipher<P, HybridAlpha> {
  mode: BlockMode;

  constructor(ctx: Group<P>, mode: BlockMode) {
    super(ctx);
    this.mode = mode;
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{
    alpha: HybridAlpha,
    decryptor: P
  }> => {
    const decryptor = await this.ctx.exp(pub, randomness);
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    let aesCiphertext;
    try {
      aesCiphertext = aes(this.mode).encrypt(key, message);
    } catch (err: any) {
      if (err instanceof AesError) throw new ElgamalError(
        'Could not encrypt' // TODO
      );
      else throw err;
    }
    const { ciphered, iv, tag } = aesCiphertext;
    return { alpha: { ciphered, iv, tag }, decryptor };
  }

  decapsulate = async (alpha: HybridAlpha, decryptor: P): Promise<Uint8Array> => {
    const { ciphered, iv, tag } = alpha;
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    try {
      return aes(this.mode).decrypt(key, ciphered, iv, tag);
    } catch (err: any) {
      if (err instanceof AesError) throw new ElgamalError(
        err.message // TODO
      );
      else throw err;
    }
  }
}

/** DHIES-Elgamal encryption (DH-based Integrated Encryption Scheme) */
export class DhiesCipher<P extends Point> extends BaseCipher<P, DhiesAlpha> {
  mode: BlockMode;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, mode: BlockMode, algorithm: Algorithms) {
    super(ctx);
    this.mode = mode;
    this.algorithm = algorithm;
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{
    alpha: DhiesAlpha,
    decryptor: P
  }> => {
    const { ctx: { generator, randomScalar, exp } } = this;
    const decryptor = await exp(pub, randomness);
    const key = await hash(Algorithms.SHA512).digest(decryptor.toBytes());
    const keyAes = key.slice(0, 32);
    const keyMac = key.slice(32, 64);
    let aesCiphertext;
    try {
      aesCiphertext = aes(this.mode).encrypt(keyAes, message);
    } catch (err: any) {
      if (err instanceof AesError) throw new ElgamalError(
        'Could not encrypt' // TODO
      );
      else throw err;
    }
    const { ciphered, iv, tag } = aesCiphertext;
    const mac = await hmac(this.algorithm, keyMac).digest(ciphered);
    return { alpha: { ciphered, iv, mac, tag }, decryptor };
  }

  decapsulate = async (alpha: DhiesAlpha, decryptor: P): Promise<Uint8Array> => {
    const { ciphered, iv, mac, tag } = alpha;
    const key = await hash(Algorithms.SHA512).digest(decryptor.toBytes());
    const keyAes = key.slice(0, 32);
    const keyMac = key.slice(32, 64);
    const targetMac = await hmac(this.algorithm, keyMac).digest(ciphered);
    let isMacValid = true;
    isMacValid &&= mac.length === targetMac.length;
    for (let i = 0; i < mac.length; i++) {
      isMacValid &&= mac[i] === targetMac[i];
    }
    if (!isMacValid) throw new ElgamalError(
      'Invalid MAC'
    );
    try {
      return aes(this.mode).decrypt(keyAes, ciphered, iv, tag);
    } catch (err: any) {
      if (err instanceof AesError) throw new ElgamalError(
        err.message // TODO
      );
      else throw err;
    }
  }
}


export function plainElgamal<P extends Point>(ctx: Group<P>) {
  return new PlainCipher(ctx);
}

export function hybridElgamal<P extends Point>(ctx: Group<P>, mode: BlockMode) {
  return new HybridCipher(ctx, mode);
}

export function dhiesElgamal<P extends Point>(ctx: Group<P>, mode: BlockMode, algorithm: Algorithm) {
  return new DhiesCipher(ctx, mode, algorithm);
}
