import { createHmac } from 'node:crypto';
import { hmac, randomBytes } from 'vsslib/crypto';
import { cartesian } from '../utils';
import { resolveTestConfig } from '../environ';

const { algorithms }  = resolveTestConfig();


describe('hmac digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(algorithms)('%s', async (algorithm) => {
    const key = randomBytes(32);
    const digest = await hmac(algorithm, key).digest(buffer);
    const hasher = createHmac(algorithm, key).update(buffer);
    const expected = Uint8Array.from(hasher.digest());
    expect(digest).toEqual(expected);
  });
});
