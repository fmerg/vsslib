import { createHash } from 'node:crypto';

import { cartesian } from './utils';
import { resolveTestConfig } from './environ';

import { hash } from 'vsslib/hash';
import { Algorithm } from 'vsslib/types';
import { InvalidInput, initBackend, createSchnorrPacket } from 'vsslib';


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

describe('hash algorithm validation', () => {
  it.each(['md5', 'sha1', 'ripemd160', 'SHA256', ''])('%s is rejected', async (algorithm) => {
    expect(() => hash(algorithm as Algorithm)).toThrow(InvalidInput);
    const ctx = initBackend('ed25519');
    const share = { value: await ctx.generateSecret(), index: 1 };
    await expect(
      createSchnorrPacket(ctx, share, { algorithm: algorithm as Algorithm })
    ).rejects.toThrow('Unsupported hash algorithm');
  });
});
