import { Algorithms, AesModes } from '../../enums';
import { Algorithm, AesMode } from '../../types';
import { Point, Group } from '../../backend/abstract';
import { ErrorMessages } from '../../errors';

import hash from '../hash';
import hmac from '../hmac';
import aes from '../aes';


/** Generic ElGamal functionality; abstracts away encapsulation details */
export abstract class BaseCipher<A, P extends Point> {
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
      beta: P
    },
    decryptor: P,
    randomness: bigint
  }> {
    const { ctx: { generator, randomScalar, operate }, encapsulate } = this;
    const randomness = await randomScalar();
    const { alpha, decryptor } = await encapsulate(pub, randomness, message);
    const beta = await operate(randomness, generator);
    return { ciphertext: { alpha, beta }, decryptor, randomness };
  }

  async decrypt(ciphertext: { alpha: A, beta: P }, secret: bigint): Promise<Uint8Array> {
    const { alpha, beta } = ciphertext;
    const isBetaValid = await this.ctx.validatePoint(beta, { raiseOnInvalid: false });
    if(!isBetaValid) throw new Error('Could not decrypt: Point not in subgroup');
    const decryptor = await this.ctx.operate(secret, beta);
    let plaintext;
    try {
      plaintext = await this.decapsulate(alpha, decryptor);
    } catch (err: any) {
      throw new Error('Could not decrypt: ' + err.message);
    }
    return plaintext;
  }

  async decryptWithDecryptor(ciphertext: { alpha: A, beta: P }, decryptor: P): Promise<Uint8Array> {
    let plaintext;
    try {
      plaintext = await this.decapsulate(ciphertext.alpha, decryptor);
    } catch (err: any) {
      throw new Error('Could not decrypt: ' + err.message);
    }
    return plaintext;
  }

  async decryptWithRandomness(ciphertext: { alpha: A, beta: P }, pub: P, randomness: bigint): Promise<
    Uint8Array
  > {
    const decryptor = await this.ctx.operate(randomness, pub);
    let plaintext;
    try {
      plaintext = await this.decapsulate(ciphertext.alpha, decryptor);
    } catch (err: any) {
      throw new Error('Could not decrypt: ' + err.message);
    }
    return plaintext;
  }
}


/** Plain Elgamal encryption, assuming messages to be valid byte representations
 * of group elements. This not CCA-secure; do *not* use it directly, unless you
 * know what you do. */
export class PlainCipher<P extends Point> extends BaseCipher<P, P> {
  constructor(ctx: Group<P>) {
    super(ctx);
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{
    alpha: P,
    decryptor: P
  }> => {
    let messagePoint;
    try {
      messagePoint = this.ctx.unpack(message);
    } catch (err: any) {
      throw new Error('Invalid point encoding: ' + err.message);
    }
    const decryptor = await this.ctx.operate(randomness, pub);
    const alpha = await this.ctx.combine(decryptor, messagePoint);
    return { alpha, decryptor };
  }

  decapsulate = async (alpha: P, decryptor: P): Promise<Uint8Array> => {
    const decryptorInverse = await this.ctx.invert(decryptor);
    const plaintext = await this.ctx.combine(alpha, decryptorInverse);
    return plaintext.toBytes();
  }
}


/** First component of a KEM-Elgamal ciphertext */
export type KemAlpha = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  tag?: Uint8Array,
};

/** KEM-Elgamal encryption (DH-based Key Encapsulation Mechanism) */
export class KemCipher<P extends Point> extends BaseCipher<KemAlpha, P> {
  mode: AesMode;

  constructor(ctx: Group<P>, mode: AesMode) {
    super(ctx);
    this.mode = mode;
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{
    alpha: KemAlpha,
    decryptor: P
  }> => {
    const decryptor = await this.ctx.operate(randomness, pub);
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    const { ciphered, iv, tag } = aes(this.mode).encrypt(key, message);
    return { alpha: { ciphered, iv, tag }, decryptor };
  }

  decapsulate = async (alpha: KemAlpha, decryptor: P): Promise<Uint8Array> => {
    const { ciphered, iv, tag } = alpha;
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    return aes(this.mode).decrypt(key, ciphered, iv, tag);
  }
}


/** First component of a IES-Elgamal ciphertext **/
export type IesAlpha = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  mac: Uint8Array,
  tag?: Uint8Array,
}

/** IES-Elgamal encryption (DH-based Integrated Encryption Scheme) */
export class IesCipher<P extends Point> extends BaseCipher<IesAlpha, P> {
  mode: AesMode;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, mode: AesMode, algorithm: Algorithms) {
    super(ctx);
    this.mode = mode;
    this.algorithm = algorithm;
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{
    alpha: IesAlpha,
    decryptor: P
  }> => {
    const { ctx: { generator, randomScalar, operate } } = this;
    const decryptor = await operate(randomness, pub);
    const key = await hash(Algorithms.SHA512).digest(decryptor.toBytes());
    const keyAes = key.slice(0, 32);
    const keyMac = key.slice(32, 64);
    const { ciphered, iv, tag } = aes(this.mode).encrypt(keyAes, message);
    const mac = await hmac(this.algorithm, keyMac).digest(ciphered);
    return { alpha: { ciphered, iv, mac, tag }, decryptor };
  }

  decapsulate = async (alpha: IesAlpha, decryptor: P): Promise<Uint8Array> => {
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
    if (!isMacValid) throw new Error(ErrorMessages.INVALID_MAC);
    const plaintext = aes(this.mode).decrypt(keyAes, ciphered, iv, tag);
    return plaintext;
  }
}


export function plain<P extends Point>(ctx: Group<P>) {
  return new PlainCipher(ctx);
}

export function kem<P extends Point>(ctx: Group<P>, mode: AesMode) {
  return new KemCipher(ctx, mode);
}

export function ies<P extends Point>(ctx: Group<P>, mode: AesMode, algorithm: Algorithm) {
  return new IesCipher(ctx, mode, algorithm);
}
