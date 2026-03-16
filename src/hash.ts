// TODO: browser
import { createHash as _createHash } from 'node:crypto';

import { Algorithm } from './types';


export class Hash {
  algorithm: Algorithm;

  constructor(algorithm: Algorithm) {
    this.algorithm = algorithm;
  }

  digest = async (buff: Uint8Array): Promise<Uint8Array> =>
    Uint8Array.from(
      _createHash(this.algorithm).update(buff).digest()
    );
}

export function hash(algorithm: Algorithm): Hash {
  return new Hash(algorithm);
}
