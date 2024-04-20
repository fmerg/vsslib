import { createHmac } from 'node:crypto';
const crypto = require('crypto');
import hmac from '../../src/core/hmac';
import { Algorithms, Encodings } from '../../src/schemes';
import { cartesian } from '../helpers';

const __algorithms  = [...Object.values(Algorithms)];
const __encodings   = [...Object.values(Encodings), undefined];


describe('hmac digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(cartesian([__algorithms, __encodings]))('%s, %s', async (algorithm, encoding) => {
    const key = crypto.randomBytes(32);
    const digest = await hmac(algorithm, key).digest(buffer, encoding);
    const hasher = createHmac(algorithm, key).update(buffer);
    const expected = encoding ?
      hasher.digest(encoding == Encodings.HEX ? Encodings.HEX : Encodings.BASE64) :
      Uint8Array.from(hasher.digest());
    expect(digest).toEqual(expected);
  });
});
