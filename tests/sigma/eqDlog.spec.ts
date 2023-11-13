import { sigma, backend } from '../../src';
import { Systems, Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/common';
import { cartesian } from '../helpers';
import { createEqDlogPairs } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('Success - without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs);
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveEqDlog(ctx, x, pairs, { nonce });
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs);
    pairs[2].v = await ctx.randomPoint();
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveEqDlog(ctx, x, pairs, { nonce });
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveEqDlog(ctx, x, pairs, { nonce });
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof, { nonce: await ctx.randomBytes()});
    expect(valid).toBe(false);
  });
});
