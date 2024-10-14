import { createHash } from 'node:crypto';

import { cartesian } from './utils';
import { resolveTestConfig } from './environ';

import hash from 'vsslib/hash';


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
