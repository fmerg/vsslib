import { Systems, Algorithms, Algorithm } from '../../../src/schemes';
import { sigma, backend } from '../../../src';
import { cartesian } from '../../helpers';
import { okamoto } from '../../../src/crypto/sigma';
import { createRepresentation } from './helpers';
import { resolveBackends, resolveAlgorithms } from '../../environ';

const __labels      = resolveBackends();
const __algorithms  = resolveAlgorithms();


describe('Success - without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
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
  it.each(__labels)('over %s', async (label) => {
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
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await okamoto(ctx, Algorithms.SHA256).prove({ s: t, t: s}, { h, u });
    const valid = await okamoto(ctx, Algorithms.SHA256).verify({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
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
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
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
  it.each(__labels)('over %s', async (label) => {
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
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await okamoto(ctx, Algorithms.SHA256).prove({ s, t }, { h, u }, nonce);
    const valid = await okamoto(ctx, Algorithms.SHA256).verify({ h, u }, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
