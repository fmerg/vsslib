import { Point, Group } from '../backend/abstract';
import { Algorithms, AesModes } from '../enums';
import { Algorithm, AesMode } from '../types';

export abstract class Ciphertext<A, P extends Point> {
  alpha: A;
  beta: P;

  constructor(alpha: A, beta: P) {
    this.alpha = alpha;
    this.beta = beta;
  }
}

export abstract class Cipher<M, A, P extends Point> {
  ctx: Group<P>;
  mode: AesMode;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, opts?: { mode?: AesMode, algorithm?: Algorithm }) {
    this.ctx = ctx;
    this.mode = opts ? (opts.mode || AesModes.DEFAULT) : AesModes.DEFAULT;
    this.algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  }

  abstract encapsulate: (pub: P, randomness: bigint, message: M) => Promise<{ alpha: A, decryptor: P }>;
  abstract decapsulate: (alpha: A, decryptor: P) => Promise<M>;

  async encrypt(message: M, pub: P): Promise<{ ciphertext: Ciphertext<A, P>, decryptor: P, randomness: bigint }> {
    const { ctx: { generator, randomScalar, operate }, encapsulate } = this;
    const randomness = await randomScalar();
    const { alpha, decryptor } = await encapsulate(pub, randomness, message);
    const beta = await operate(randomness, generator);
    return { ciphertext: { alpha, beta }, decryptor, randomness };
  }

  async decrypt(ciphertext: Ciphertext<A, P>, secret: bigint): Promise<M> {
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

  async decryptWithDecryptor(ciphertext: Ciphertext<A, P>, decryptor: P): Promise<M> {
    let plaintext;
    try {
      plaintext = await this.decapsulate(ciphertext.alpha, decryptor);
    } catch (err: any) {
      throw new Error('Could not decrypt: ' + err.message);
    }
    return plaintext;
  }

  async decryptWithRandomness(ciphertext: Ciphertext<A, P>, pub: P, randomness: bigint): Promise<M> {
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
