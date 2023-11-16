import { Group, Point } from '../backend/abstract';
import { Cipher, Ciphertext } from './common';


export class ElGamalCiphertext<P extends Point> extends Ciphertext<P, P> {
}

export class ElGamalCipher<P extends Point> extends Cipher<P, P, P> {
  constructor(ctx: Group<P>) {
    super(ctx);
  }

  encapsulate = async (pub: P, randomness: bigint, message: P): Promise<{ alpha: P, decryptor: P }> => {
    const decryptor = await this.ctx.operate(randomness, pub);
    const alpha = await this.ctx.combine(decryptor, message);
    return { alpha, decryptor };
  }

  decapsulate = async (alpha: P, decryptor: P): Promise<P> => {
    return this.ctx.combine(alpha, await this.ctx.invert(decryptor));
  }
}

export default function<P extends Point>(ctx: Group<P>) {
  return new ElGamalCipher(ctx);
}
