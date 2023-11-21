import { backend } from '../../src';
import { Systems, Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { cartesian } from '../helpers';
import { createLinearRelation } from './helpers';
import { linearDlog } from '../../src/sigma';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Success - without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx, algorithm).prove(witnesses, relation);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await linearDlog(ctx).verify(relation, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const nonce = await ctx.randomBytes();
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx).prove(witnesses, relation, nonce);
    const valid = await linearDlog(ctx).verify(relation, proof, nonce);
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx).prove(witnesses, relation);
    proof.response[0] = await ctx.randomScalar();
    const valid = await linearDlog(ctx).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await linearDlog(ctx, algorithm).prove(witnesses, relation);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await linearDlog(ctx).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await linearDlog(ctx).prove(witnesses, relation, nonce);
    const valid = await linearDlog(ctx).verify(relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await linearDlog(ctx).prove(witnesses, relation, nonce);
    const valid = await linearDlog(ctx).verify(relation, proof, await ctx.randomBytes());
    expect(valid).toBe(false);
  });
});
