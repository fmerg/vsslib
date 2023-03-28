// TODO: browser
import { createHash } from 'node:crypto';
import { Algorithms } from '../enums';
import { Algorithm, Encoding } from '../types';
import { assertAlgorithm, assertEncoding } from './checkers';


export default async function(
  buffer: Uint8Array,
  opts?: {
    algorithm?: Algorithm,
    encoding?: Encoding,
  }
): Promise<string | Uint8Array> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const encoding = opts ? opts.encoding : undefined;
  assertAlgorithm(algorithm);
  if (encoding) assertEncoding(encoding);
  const hasher = createHash(algorithm).update(buffer);
  return encoding ? hasher.digest(encoding) : new Uint8Array(hasher.digest());
}
