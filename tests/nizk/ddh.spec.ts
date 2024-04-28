import { Algorithms } from '../../src/enums';
import { backend } from '../../src';
import { cartesian } from '../helpers';
import { createDDHTuple } from './helpers';
import { ddh } from '../../src/nizk';
import { resolveTestConfig } from '../environ';

let { labels, algorithms } = resolveTestConfig();



describe('Success - without nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await ddh(ctx, algorithm).prove(z, { u, v, w });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await ddh(ctx, algorithm).verify({ u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await ddh(ctx, Algorithms.SHA256).prove(z, { u, v, w }, nonce);
    const valid = await ddh(ctx, Algorithms.SHA256).verify({ u, v, w }, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await ddh(ctx, Algorithms.SHA256).prove(z, { u, v, w })
    proof.response[0] = await ctx.randomScalar();
    const valid = await ddh(ctx, Algorithms.SHA256).verify({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const proof = await ddh(ctx, algorithm).prove(z, { u, v, w })
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await ddh(ctx, algorithm).verify({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
})


describe('Failure - missing nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await ddh(ctx, Algorithms.SHA256).prove(z, { u, v, w }, nonce);
    const valid = await ddh(ctx, Algorithms.SHA256).verify({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await ddh(ctx, Algorithms.SHA256).prove(z, { u, v, w }, nonce);
    const valid = await ddh(ctx, Algorithms.SHA256).verify({ u, v, w }, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
