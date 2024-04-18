import { backend } from '../../../src';
import { Systems, Algorithms } from '../../../src/enums';
import { Algorithm } from '../../../src/types';
import { cartesian } from '../../helpers';
import { createDlogPair } from './helpers';
import { dlog } from '../../../src/core/sigma';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Success - without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await dlog(ctx, algorithm).prove(x, { u, v });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await dlog(ctx).verify({ u, v }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await dlog(ctx).prove(x, { u, v }, nonce);
    const valid = await dlog(ctx).verify({ u, v }, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await dlog(ctx).prove(x, { u, v });
    proof.response[0] = await ctx.randomScalar();
    const valid = await dlog(ctx).verify({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await dlog(ctx, algorithm).prove(x, { u, v });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await dlog(ctx).verify({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await dlog(ctx).prove(x, { u, v }, nonce);
    const valid = await dlog(ctx).verify({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await dlog(ctx).prove(x, { u, v }, nonce);
    const valid = await dlog(ctx).verify({ u, v }, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
