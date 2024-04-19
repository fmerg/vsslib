// TODO: browser
import { createHmac, Hmac as _Hmac } from 'node:crypto';
import { Algorithms } from '../enums';
import { Algorithm, Encoding } from '../types';
import { assertAlgorithm, assertEncoding } from '../utils/checkers';


export class Hmac {
  _hmac: _Hmac;

  constructor(algorithm: Algorithm, key: Uint8Array) {
    assertAlgorithm(algorithm);
    this._hmac = createHmac(algorithm, key);
  }

  async digest(buffer: Uint8Array, encoding?: Encoding): Promise<string | Uint8Array> {
    const hasher = this._hmac.update(buffer);
    if (encoding) assertEncoding(encoding);
    return encoding ? hasher.digest(encoding) : Uint8Array.from(hasher.digest());
  }
}

export default function(algorithm: Algorithm, key: Uint8Array): Hmac {
  return new Hmac(algorithm, key);
}
