import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { createRepresentation } from './helpers';
import { resolveTestConfig } from '../environ';
import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await nizk(ctx, algorithm).proveRepresentation({ s, t }, { h, u });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await nizk(ctx, algorithm).verifyRepresentation({ h, u }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await nizk(ctx, Algorithms.SHA256).proveRepresentation({ s, t }, { h, u }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyRepresentation({ h, u }, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - if swaped scalar factors', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await nizk(ctx, Algorithms.SHA256).proveRepresentation({ s: t, t: s}, { h, u });
    const valid = await nizk(ctx, Algorithms.SHA256).verifyRepresentation({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if tampered proof', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await nizk(ctx, Algorithms.SHA256).proveRepresentation({ s, t }, { h, u });
    proof.response[0] = await ctx.randomScalar();
    const valid = await nizk(ctx, Algorithms.SHA256).verifyRepresentation({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await nizk(ctx, algorithm).proveRepresentation({ s, t }, { h, u });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await nizk(ctx, algorithm).verifyRepresentation({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await nizk(ctx, Algorithms.SHA256).proveRepresentation({ s, t }, { h, u }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyRepresentation({ h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await nizk(ctx, Algorithms.SHA256).proveRepresentation({ s, t }, { h, u }, nonce);
    const valid = await nizk(ctx, Algorithms.SHA256).verifyRepresentation({ h, u }, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
