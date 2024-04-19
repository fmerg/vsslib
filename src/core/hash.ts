// TODO: browser
import { createHash, Hash as _Hash } from 'node:crypto';
import { Algorithms } from '../enums';
import { Algorithm, Encoding } from '../types';
import { assertAlgorithm, assertEncoding } from '../utils/checkers';


export class Hash {
  _hash: _Hash;

  constructor(algorithm: Algorithm) {
    assertAlgorithm(algorithm);
    this._hash = createHash(algorithm);
  }

  async digest(buffer: Uint8Array, encoding?: Encoding): Promise<string | Uint8Array> {
    const hasher = this._hash.update(buffer);
    if (encoding) assertEncoding(encoding);
    return encoding ? hasher.digest(encoding) : Uint8Array.from(hasher.digest());
  }

}

export default function(algorithm?: Algorithm): Hash {
  return new Hash(algorithm || Algorithms.DEFAULT);
}
