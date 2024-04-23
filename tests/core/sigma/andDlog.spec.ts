import { Systems, Algorithms, Algorithm } from '../../../src/schemes';
import { backend } from '../../../src';
import { cartesian } from '../../helpers';
import { createAndDlogPairs } from './helpers';
import { andDlog } from '../../../src/core/sigma';
import { resolveBackends, resolveAlgorithms } from '../../environ';

const __labels      = resolveBackends();
const __algorithms  = resolveAlgorithms();



describe('Success - without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, algorithm).prove(witnesses, pairs);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await andDlog(ctx, algorithm).verify(pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs, nonce);
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs);
    proof.response[0] = await ctx.randomScalar();
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, algorithm).prove(witnesses, pairs);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await andDlog(ctx, algorithm).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs, nonce);
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const nonce = await ctx.randomBytes();
    const [witnesses, pairs] = await createAndDlogPairs(ctx, 5);
    const proof = await andDlog(ctx, Algorithms.SHA256).prove(witnesses, pairs, nonce);
    const valid = await andDlog(ctx, Algorithms.SHA256).verify(pairs, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});


