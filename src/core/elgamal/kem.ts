import { Algorithms, Algorithm, AesModes, AesMode } from '../../schemes';
import { Point, Group } from '../../backend/abstract';
import { BaseCipher, Ciphertext } from './base';


import hash from '../hash';
import aes from '../aes';


type A = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  tag?: Uint8Array,
};

export class KemCiphertext<P extends Point> extends Ciphertext<A, P> {
}


export class KemCipher<P extends Point> extends BaseCipher<Uint8Array, A, P> {
  mode: AesMode;

  constructor(ctx: Group<P>, mode: AesMode) {
    super(ctx);
    this.mode = mode;
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{ alpha: A, decryptor: P }> => {
    const decryptor = await this.ctx.operate(randomness, pub);
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    const { ciphered, iv, tag } = aes(this.mode).encrypt(key, message);
    return { alpha: { ciphered, iv, tag }, decryptor };
  }

  decapsulate = async (alpha: A, decryptor: P): Promise<Uint8Array> => {
    const { ciphered, iv, tag } = alpha;
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    return aes(this.mode).decrypt(key, ciphered, iv, tag);
  }
}

export default function<P extends Point>(ctx: Group<P>, mode: AesMode) {
  return new KemCipher(ctx, mode);
}
