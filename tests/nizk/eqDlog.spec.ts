import { Algorithms } from '../../src/enums';
import { backend } from '../../src';
import { cartesian } from '../helpers';
import { createEqDlogPairs } from './helpers';
import { eqDlog } from '../../src/nizk';
import { resolveTestConfig } from '../environ';

let { labels, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await eqDlog(ctx, algorithm).prove(x, pairs);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await eqDlog(ctx, algorithm).verify(pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await eqDlog(ctx, Algorithms.SHA256).prove(x, pairs, nonce);
    const valid = await eqDlog(ctx, Algorithms.SHA256).verify(pairs, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await eqDlog(ctx, Algorithms.SHA256).prove(x, pairs);
    pairs[2].v = await ctx.randomPoint();
    const valid = await eqDlog(ctx, Algorithms.SHA256).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await eqDlog(ctx, algorithm).prove(x, pairs);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await eqDlog(ctx, algorithm).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await eqDlog(ctx, Algorithms.SHA256).prove(x, pairs, nonce);
    const valid = await eqDlog(ctx, Algorithms.SHA256).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await eqDlog(ctx, Algorithms.SHA256).prove(x, pairs, nonce);
    const valid = await eqDlog(ctx, Algorithms.SHA256).verify(pairs, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
