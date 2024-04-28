import { Algorithms } from '../../src/enums';
import { backend } from '../../src';
import { cartesian } from '../helpers';
import { okamoto } from '../../src/nizk';
import { createRepresentation } from './helpers';
import { resolveTestConfig } from '../environ';

let { labels, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await okamoto(ctx, algorithm).prove({ s, t }, { h, u });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await okamoto(ctx, algorithm).verify({ h, u }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await okamoto(ctx, Algorithms.SHA256).prove({ s, t }, { h, u }, nonce);
    const valid = await okamoto(ctx, Algorithms.SHA256).verify({ h, u }, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - if swaped scalar factors', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await okamoto(ctx, Algorithms.SHA256).prove({ s: t, t: s}, { h, u });
    const valid = await okamoto(ctx, Algorithms.SHA256).verify({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if tampered proof', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await okamoto(ctx, Algorithms.SHA256).prove({ s, t }, { h, u });
    proof.response[0] = await ctx.randomScalar();
    const valid = await okamoto(ctx, Algorithms.SHA256).verify({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if wrong algorithm', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await okamoto(ctx, algorithm).prove({ s, t }, { h, u });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await okamoto(ctx, algorithm).verify({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if missing nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await okamoto(ctx, Algorithms.SHA256).prove({ s, t }, { h, u }, nonce);
    const valid = await okamoto(ctx, Algorithms.SHA256).verify({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if forged nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await okamoto(ctx, Algorithms.SHA256).prove({ s, t }, { h, u }, nonce);
    const valid = await okamoto(ctx, Algorithms.SHA256).verify({ h, u }, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
