import { sigma, backend } from '../../src';
import { Systems, Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { cartesian } from '../helpers';
import { createLinearRelation } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Success - without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
    const valid = await sigma.verifyLinearRelation(ctx, relation, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const nonce = await ctx.randomBytes();
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation, { nonce });
    const valid = await sigma.verifyLinearRelation(ctx, relation, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Failure - forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyLinearRelation(ctx, relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyLinearRelation(ctx, relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation, { nonce });
    const valid = await sigma.verifyLinearRelation(ctx, relation, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation, { nonce });
    const valid = await sigma.verifyLinearRelation(ctx, relation, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});
