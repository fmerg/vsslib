import { Encodings } from '../src/schemes';
import { generateKey } from '../src/core';
import { PrivateShare, PublicShare } from '../src/sharing';
import { initGroup } from '../src/backend';
import { cartesian } from './helpers';
import { resolveTestConfig } from './environ';
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

const { labels, encodings } = resolveTestConfig();

describe('Private key serialization roundtrip', () => {
  it.each(cartesian([labels, encodings]))('over %s/%s', async (label, encoding) => {
    const { privateKey, ctx } = await generateKey(label);
    const data = serializePrivateKey(privateKey, encoding);
    expect(data).toEqual({
      value: Buffer.from(privateKey.bytes).toString(encoding),
      system: ctx.label,
      encoding: encoding,
    });
    const privateBack = await deserializePrivateKey(data);
    expect(await privateBack.equals(privateKey)).toBe(true);
  });
});

describe('Public key serialization roundtrip', () => {
  it.each(cartesian([labels, encodings]))('over %s/%s', async (label, encoding) => {
    const { publicKey, ctx } = await generateKey(label);
    const data = serializePublicKey(publicKey, encoding);
    expect(data).toEqual({
      value: Buffer.from(publicKey.bytes).toString(encoding),
      system: ctx.label,
      encoding: encoding,
    });
    const publicBack = await deserializePublicKey(data)
    expect(await publicBack.equals(publicKey)).toBe(true);
  });
});


describe('Private share serialization roundtrip', () => {
  it.each(cartesian([labels, encodings]))('over %s/%s', async (label, encoding) => {
    const ctx = initGroup(label);
    const privateShare = new PrivateShare(ctx, await ctx.randomScalar(), 666);
    const data = serializePrivateShare(privateShare, encoding);
    expect(data).toEqual({
      value: Buffer.from(privateShare.bytes).toString(encoding),
      system: ctx.label,
      encoding: encoding,
      index: 666,
    });
    const privateBack = await deserializePrivateShare(data);
    expect(await privateBack.equals(privateShare)).toBe(true);
  });
});

describe('Public share serialization roundtrip', () => {
  it.each(cartesian([labels, encodings]))('over %s/%s', async (label, encoding) => {
    const ctx = initGroup(label);
    const publicShare = new PublicShare(ctx, await ctx.randomPoint(), 999);
    const data = serializePublicShare(publicShare, encoding);
    expect(data).toEqual({
      value: Buffer.from(publicShare.bytes).toString(encoding),
      system: ctx.label,
      encoding: encoding,
      index: 999,
    });
    const publicBack = await deserializePublicShare(data);
    expect(await publicBack.equals(publicShare)).toBe(true);
  });
});
