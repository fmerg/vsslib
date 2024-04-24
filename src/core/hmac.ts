// TODO: browser
import { createHmac as _createHmac } from 'node:crypto';

import { Algorithm } from '../schemes';


export class Hmac {
  algorithm: Algorithm;
  key: Uint8Array;

  constructor(algorithm: Algorithm, key: Uint8Array) {
    this.algorithm = algorithm;
    this.key = key;
  }

  async digest(buffer: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(_createHmac(this.algorithm, this.key).update(buffer).digest());
  }
}

export default function(algorithm: Algorithm, key: Uint8Array): Hmac {
  return new Hmac(algorithm, key);
}
