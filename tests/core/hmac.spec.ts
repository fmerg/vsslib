import { createHmac, randomBytes } from 'node:crypto';

import { Algorithms, Encodings } from '../../src/schemes';
import hmac from '../../src/core/hmac';

import { cartesian } from '../helpers';
import { resolveAlgorithms, resolveEncodings } from '../environ';

const __algorithms  = resolveAlgorithms();
const __encodings   = [...resolveEncodings(), undefined];


describe('hmac digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(cartesian([__algorithms, __encodings]))('%s, %s', async (algorithm, encoding) => {
    const key = randomBytes(32);
    const digest = await hmac(algorithm, key).digest(buffer, encoding);
    const hasher = createHmac(algorithm, key).update(buffer);
    const expected = encoding ?
      hasher.digest(encoding == Encodings.HEX ? Encodings.HEX : Encodings.BASE64) :
      Uint8Array.from(hasher.digest());
    expect(digest).toEqual(expected);
  });
});
