// TODO: browser
import { createHmac, Hmac as _Hmac } from 'node:crypto';
import { Algorithms, Algorithm, Encoding } from '../schemes';


export class Hmac {
  _hmac: _Hmac;

  constructor(algorithm: Algorithm, key: Uint8Array) {
    this._hmac = createHmac(algorithm, key);
  }

  async digest(buffer: Uint8Array, encoding?: Encoding): Promise<string | Uint8Array> {
    const hasher = this._hmac.update(buffer);
    return encoding ? hasher.digest(encoding) : Uint8Array.from(hasher.digest());
  }
}

export default function(algorithm: Algorithm, key: Uint8Array): Hmac {
  return new Hmac(algorithm, key);
}
