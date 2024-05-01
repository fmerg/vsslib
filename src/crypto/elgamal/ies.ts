import { Algorithms } from '../../enums';
import { Algorithm, AesMode } from '../../types';
import { Point, Group } from '../../backend/abstract';
import { BaseCipher, Ciphertext } from './base';
import { ErrorMessages } from '../../errors';

import aes from '../aes';
import hash from '../hash';
import hmac from '../hmac';


type A = {
  ciphered: Uint8Array,
  iv: Uint8Array,
  mac: Uint8Array,
  tag?: Uint8Array,
}

export class IesCiphertext<P extends Point> extends Ciphertext<A, P> {
}

export class IesCipher<P extends Point> extends BaseCipher<Uint8Array, A, P> {
  mode: AesMode;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, mode: AesMode, algorithm: Algorithms) {
    super(ctx);
    this.mode = mode;
    this.algorithm = algorithm;
  }

  encapsulate = async (pub: P, randomness: bigint, message: Uint8Array): Promise<{ alpha: A, decryptor: P }> => {
    const { ctx: { generator, randomScalar, operate } } = this;
    const decryptor = await operate(randomness, pub);
    const key = await hash(Algorithms.SHA512).digest(decryptor.toBytes());
    const keyAes = key.slice(0, 32);
    const keyMac = key.slice(32, 64);
    const { ciphered, iv, tag } = aes(this.mode).encrypt(keyAes, message);
    const mac = await hmac(this.algorithm, keyMac).digest(ciphered);
    return { alpha: { ciphered, iv, mac, tag }, decryptor };
  }

  decapsulate = async (alpha: A, decryptor: P): Promise<Uint8Array> => {
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

export default function<P extends Point>(ctx: Group<P>, mode: AesMode, algorithm: Algorithm) {
  return new IesCipher(ctx, mode, algorithm);
}
