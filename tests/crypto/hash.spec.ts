import hash from '../../src/crypto/hash';
import { createHash } from 'node:crypto';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';


const { algorithms }  = resolveTestConfig()

describe('hash digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(algorithms)('%s', async (algorithm) => {
    const digest = await hash(algorithm).digest(buffer);
    const hasher = createHash(algorithm).update(buffer);
    const expected = Uint8Array.from(hasher.digest());
    expect(digest).toEqual(expected);
  });
});
