import { Systems, Algorithms, Algorithm } from '../../src/schemes';
import { backend } from '../../src';
import { cartesian } from '../helpers';
import { createLinearRelation } from './helpers';
import { linearDlog } from '../../src/nizk';
import { resolveTestConfig } from '../environ';

let { labels, algorithms } = resolveTestConfig();


describe('Success - without nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx, algorithm).prove(witnesses, relation);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await linearDlog(ctx, algorithm).verify(relation, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const nonce = await ctx.randomBytes();
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx, Algorithms.SHA256).prove(witnesses, relation, nonce);
    const valid = await linearDlog(ctx, Algorithms.SHA256).verify(relation, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx, Algorithms.SHA256).prove(witnesses, relation);
    proof.response[0] = await ctx.randomScalar();
    const valid = await linearDlog(ctx, Algorithms.SHA256).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx, algorithm).prove(witnesses, relation);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await linearDlog(ctx, algorithm).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await linearDlog(ctx, Algorithms.SHA256).prove(witnesses, relation, nonce);
    const valid = await linearDlog(ctx, Algorithms.SHA256).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await linearDlog(ctx, Algorithms.SHA256).prove(witnesses, relation, nonce);
    const valid = await linearDlog(ctx, Algorithms.SHA256).verify(relation, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
