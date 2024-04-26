import { Algorithms, Algorithm, Systems } from '../src/schemes';
import { generateKey } from '../src/core';
import { PrivateShare, PublicShare } from '../src/sharing';
import { initGroup } from '../src/backend';
import { cartesian } from './helpers';
import { resolveBackends } from './environ';
import {
  serializePrivateKey,
  serializePublicKey,
  serializePrivateShare,
  serializePublicShare,
  deserializePrivateKey,
  deserializePublicKey,
  deserializePrivateShare,
  deserializePublicShare,
} from '../src/serializers';

const __labels = resolveBackends();

describe('Private key serialization roundtrip', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, ctx } = await generateKey(label);
    const data = serializePrivateKey(privateKey);
    expect(data).toEqual({
      value: Buffer.from(privateKey.bytes).toString('hex'),
      system: ctx.label,
    });
    const privateBack = await deserializePrivateKey(data);
    expect(await privateBack.equals(privateKey)).toBe(true);
  });
});

describe('Public key serialization roundtrip', () => {
  it.each(__labels)('over %s', async (label) => {
    const { publicKey, ctx } = await generateKey(label);
    const data = serializePublicKey(publicKey);
    expect(data).toEqual({
      value: Buffer.from(publicKey.bytes).toString('hex'),
      system: ctx.label,
    });
    const publicBack = await deserializePublicKey(data)
    expect(await publicBack.equals(publicKey)).toBe(true);
  });
});


describe('Private share serialization roundtrip', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = initGroup(label);
    const privateShare = new PrivateShare(ctx, await ctx.randomScalar(), 666);
    const data = serializePrivateShare(privateShare);
    expect(data).toEqual({
      value: Buffer.from(privateShare.bytes).toString('hex'),
      system: ctx.label,
      index: 666,
    });
    const privateBack = await deserializePrivateShare(data);
    expect(await privateBack.equals(privateShare)).toBe(true);
  });
});

describe('Public share serialization roundtrip', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = initGroup(label);
    const publicShare = new PublicShare(ctx, await ctx.randomPoint(), 999);
    const data = serializePublicShare(publicShare);
    expect(data).toEqual({
      value: Buffer.from(publicShare.bytes).toString('hex'),
      system: ctx.label,
      index: 999,
    });
    const publicBack = await deserializePublicShare(data);
    expect(await publicBack.equals(publicShare)).toBe(true);
  });
});
