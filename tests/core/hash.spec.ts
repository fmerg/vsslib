import { createHash } from 'node:crypto';
import { Algorithms, Encodings } from '../../src/schemes';
import hash from '../../src/core/hash';
import { cartesian } from '../helpers';

const __algorithms  = [...Object.values(Algorithms), undefined];
const __encodings   = [...Object.values(Encodings), undefined];


describe('hash digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(cartesian([__algorithms, __encodings]))('%s, %s', async (algorithm, encoding) => {
    const digest = await hash(algorithm).digest(buffer, encoding);
    const hasher = createHash(algorithm || Algorithms.DEFAULT).update(buffer);
    const expected = encoding ?
      hasher.digest(encoding == Encodings.HEX ? Encodings.HEX : Encodings.BASE64) :
      Uint8Array.from(hasher.digest());
    expect(digest).toEqual(expected);
  });
});
