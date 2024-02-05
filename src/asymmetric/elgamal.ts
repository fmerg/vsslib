import { Group, Point } from '../backend/abstract';
import { BaseCipher, Ciphertext } from './common';


export class ElGamalCiphertext<P extends Point> extends Ciphertext<P, P> {
}

export class ElGamalCipher<P extends Point> extends BaseCipher<Uint8Array, P, P> {
  constructor(ctx: Group<P>) {
    super(ctx);
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{ alpha: P, decryptor: P }> => {
    // TODO: Handle invalid point error
    const messagePoint = this.ctx.unpack(message)
    const decryptor = await this.ctx.operate(randomness, pub);
    const alpha = await this.ctx.combine(decryptor, messagePoint);
    return { alpha, decryptor };
  }

  decapsulate = async (alpha: P, decryptor: P): Promise<Uint8Array> => {
    const plaintextPoint = await this.ctx.combine(alpha, await this.ctx.invert(decryptor));
    return plaintextPoint.toBytes();
  }
}

export default function<P extends Point>(ctx: Group<P>) {
  return new ElGamalCipher(ctx);
}
