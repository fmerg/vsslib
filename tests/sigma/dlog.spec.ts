import { sigma, backend } from '../../src';
import { Systems, Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/common';
import { cartesian } from '../helpers';
import { createDlogPair } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Success - without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v });
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDlog(ctx, x, { u, v }, { nonce});
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v });
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDlog(ctx, x, { u, v }, { nonce });
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDlog(ctx, x, { u, v }, { nonce });
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});
