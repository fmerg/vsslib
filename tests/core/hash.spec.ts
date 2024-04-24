import { createHash } from 'node:crypto';

import hash from '../../src/core/hash';

import { cartesian } from '../helpers';
import { resolveAlgorithms } from '../environ';

const __algorithms  = resolveAlgorithms()


describe('hash digest', () => {
  const buffer = Buffer.from('sample-text');
  it.each(__algorithms)('%s', async (algorithm) => {
    const digest = await hash(algorithm).digest(buffer);
    const hasher = createHash(algorithm).update(buffer);
    const expected = Uint8Array.from(hasher.digest());
    expect(digest).toEqual(expected);
  });
});
