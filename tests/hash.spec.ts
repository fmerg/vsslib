import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { createHash } from 'node:crypto';

import { resolveTestConfig } from './environ';

import { hash } from 'vsslib/hash';
import { Algorithm } from 'vsslib/types';
import { InvalidInput, initBackend, createSchnorrPacket, Algorithms } from 'vsslib';


const { algorithms }  = resolveTestConfig()

describe('hash digest', () => {
  const buffer = Buffer.from('sample-text');
  each(algorithms)('%s', async (algorithm) => {
    const digest = await hash(algorithm).digest(buffer);
    const hasher = createHash(algorithm).update(buffer);
    const expected = Uint8Array.from(hasher.digest());
    assert.deepEqual(digest, expected);
  });
});

describe('hash digest at block boundaries', () => {
  // Lengths around the padding and block sizes of SHA-2 (64, 128) and SHA-3 (72-144)
  const lengths = [0, 1, 55, 56, 63, 64, 65, 71, 72, 103, 104, 111, 112, 127, 128, 135,
    136, 143, 144, 1000];
  each(algorithms)('%s', async (algorithm) => {
    for (const len of lengths) {
      const buffer = Uint8Array.from({ length: len }, (_, i) => (i * 7 + len) & 0xff);
      const digest = await hash(algorithm).digest(buffer);
      const expected = Uint8Array.from(createHash(algorithm).update(buffer).digest());
      assert.deepEqual(digest, expected);
    }
  });
});

describe('hash algorithm support', () => {
  // All algorithms regardless of the test config, so that a mismatched hasher is caught
  const buffer = Buffer.from('sample-text');
  each(Object.values(Algorithms))('%s is supported', async (algorithm) => {
    const hasher = hash(algorithm);
    assert.equal(hasher.algorithm, algorithm);
    const expected = Uint8Array.from(createHash(algorithm).update(buffer).digest());
    assert.deepEqual(await hasher.digest(buffer), expected);
  });
});

describe('hash algorithm validation', () => {
  each(['md5', 'sha1', 'ripemd160', 'SHA256', ''])('%s is rejected', async (algorithm) => {
    assert.throws(() => hash(algorithm as Algorithm), InvalidInput);
    const ctx = initBackend('ed25519');
    const share = { value: await ctx.generateSecret(), index: 1 };
    await assert.rejects(createSchnorrPacket(ctx, share, { algorithm: algorithm as Algorithm }), /Unsupported hash algorithm/);
  });
});
