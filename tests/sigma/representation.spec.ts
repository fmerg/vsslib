import { sigma, backend } from '../../src';
import { Systems, Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/common';
import { cartesian } from '../helpers';
import { createRepresentation } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('Success - without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(true);
  });
});


describe('Success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u }, { nonce });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Failure - if swaped scalar factors', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s: t, t: s}, { h, u });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u });
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u });
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u }, { nonce });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Failure - if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u }, { nonce });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});
