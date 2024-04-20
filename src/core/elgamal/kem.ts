import { Algorithms, Algorithm, AesModes, AesMode } from '../../schemes';
import { Point, Group } from '../../backend/abstract';
import { BaseCipher, Ciphertext } from './base';


const aes = require('../aes');
import hash from '../hash';


type A = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  tag?: Uint8Array,
  mode: AesMode,
};

export class KemCiphertext<P extends Point> extends Ciphertext<A, P> {
}


export class KemCipher<P extends Point> extends BaseCipher<Uint8Array, A, P> {
  constructor(ctx: Group<P>, opts?: { mode?: AesMode }) {
    super(ctx, opts);
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{ alpha: A, decryptor: P }> => {
    const { ctx, mode } = this;
    const decryptor = await ctx.operate(randomness, pub);
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    const { ciphered, iv, tag } = aes.encrypt(key, message, { mode });
    return { alpha: { ciphered, iv, tag, mode }, decryptor };
  }

  decapsulate = async (alpha: A, decryptor: P): Promise<Uint8Array> => {
    const { ciphered, iv, tag, mode } = alpha;
    const key = await hash(Algorithms.SHA256).digest(decryptor.toBytes());
    return aes.decrypt(key, ciphered, iv, { mode, tag });
  }
}

export default function<P extends Point>(ctx: Group<P>, opts?: { mode?: AesMode }) {
  return new KemCipher(ctx, opts);
}
