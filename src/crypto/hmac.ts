// TODO: browser
import { createHmac as _createHmac } from 'node:crypto';

import { Algorithm } from 'vsslib/types';


export class Hmac {
  algorithm: Algorithm;
  key: Uint8Array;

  constructor(algorithm: Algorithm, key: Uint8Array) {
    this.algorithm = algorithm;
    this.key = key;
  }

  digest = async (buff: Uint8Array): Promise<Uint8Array> =>
    Uint8Array.from(
      _createHmac(this.algorithm, this.key).update(buff).digest()
    )
}

export default function(algorithm: Algorithm, key: Uint8Array): Hmac {
  return new Hmac(algorithm, key);
}
