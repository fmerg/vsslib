import { createHmac } from 'node:crypto';

import { randomBytes } from '../../src/crypto/random';
import hmac from '../../src/crypto/hmac';

import { cartesian } from '../helpers';
import { resolveAlgorithms } from '../environ';

const __algorithms  = resolveAlgorithms();


describe('hmac digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(__algorithms)('%s', async (algorithm) => {
    const key = randomBytes(32);
    const digest = await hmac(algorithm, key).digest(buffer);
    const hasher = createHmac(algorithm, key).update(buffer);
    const expected = Uint8Array.from(hasher.digest());
    expect(digest).toEqual(expected);
  });
});
