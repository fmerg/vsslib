// TODO: browser
import { createHash as _createHash } from 'node:crypto';

import { Algorithm } from './types';
import { Algorithms } from './enums';
import { InvalidInput } from './errors';


const SUPPORTED = new Set<string>(Object.values(Algorithms));


export class Hash {
  algorithm: Algorithm;

  constructor(algorithm: Algorithm) {
    // The type does not constrain JS callers
    if (!SUPPORTED.has(algorithm)) throw new InvalidInput(
      `Unsupported hash algorithm: ${algorithm}`
    );
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
