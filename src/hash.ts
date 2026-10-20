import { sha224, sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { sha3_224, sha3_256, sha3_384, sha3_512 } from '@noble/hashes/sha3.js';

import { Algorithm } from './types';
import { Algorithms } from './enums';
import { InvalidInput } from './errors';


const HASHERS = new Map<string, (msg: Uint8Array) => Uint8Array>([
  [Algorithms.SHA224, sha224],
  [Algorithms.SHA256, sha256],
  [Algorithms.SHA384, sha384],
  [Algorithms.SHA512, sha512],
  [Algorithms.SHA3_224, sha3_224],
  [Algorithms.SHA3_256, sha3_256],
  [Algorithms.SHA3_384, sha3_384],
  [Algorithms.SHA3_512, sha3_512],
]);


export class Hash {
  readonly algorithm: Algorithm;
  private hasher: (msg: Uint8Array) => Uint8Array;

  constructor(algorithm: Algorithm) {
    // The type does not constrain JS callers
    const hasher = HASHERS.get(algorithm);
    if (!hasher) throw new InvalidInput(
      `Unsupported hash algorithm: ${algorithm}`
    );
    this.algorithm = algorithm;
    this.hasher = hasher;
  }

  digest = async (buff: Uint8Array): Promise<Uint8Array> => this.hasher(buff);
}

export function hash(algorithm: Algorithm): Hash {
  return new Hash(algorithm);
}
