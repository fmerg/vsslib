// TODO: browser
import { createHash as _createHash } from 'node:crypto';

import { Algorithm } from '../schemes';


export class Hash {
  algorithm: Algorithm;

  constructor(algorithm: Algorithm) {
    this.algorithm = algorithm;
  }

  async digest(buffer: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(_createHash(this.algorithm).update(buffer).digest());
  }
}

export default function(algorithm: Algorithm): Hash {
  return new Hash(algorithm);
}
