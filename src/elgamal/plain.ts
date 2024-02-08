import { Group, Point } from '../backend/abstract';
import { BaseCipher, Ciphertext } from './base';


export class PlainCiphertext<P extends Point> extends Ciphertext<P, P> {
}

export class PlainCipher<P extends Point> extends BaseCipher<Uint8Array, P, P> {
  constructor(ctx: Group<P>) {
    super(ctx);
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{ alpha: P, decryptor: P }> => {
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
    const plaintextPoint = await this.ctx.combine(alpha, await this.ctx.invert(decryptor));
    return plaintextPoint.toBytes();
  }
}

export default function<P extends Point>(ctx: Group<P>) {
  return new PlainCipher(ctx);
}
