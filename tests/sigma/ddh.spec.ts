import { sigma, backend } from '../../src';
import { Systems, Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/common';
import { cartesian } from '../helpers';
import { createDDHTuple } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Success - without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { nonce });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w })
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w })
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
})


describe('Failure - missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { nonce });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { nonce });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});
