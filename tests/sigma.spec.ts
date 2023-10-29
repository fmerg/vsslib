import { CryptoSystem } from '../src/elgamal/core';
import { Point } from '../src/backend/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { cartesian } from './helpers';

const elgamal = require('../src/elgamal');
const sigma = require('../src/sigma');
const backend = require('../src/backend');
const helpers = require('./helpers');



const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('multiple AND dlog proof success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const pairs = await helpers.createDlogPairs(ctx, z, 3);
    const proof = await sigma.proveEqDlog(ctx, z, pairs, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('multiple AND dlog proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const pairs = await helpers.createDlogPairs(ctx, z, 3);
    const proof = await sigma.proveEqDlog(ctx, z, pairs);

    // Tamper last pair
    pairs[2].v = await ctx.randomPoint();

    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('multiple AND dlog proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const pairs = await helpers.createDlogPairs(ctx, z, 3);
    const proof = await sigma.proveEqDlog(ctx, z, pairs);

    // Change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('dlog proof success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await sigma.proveDlog(ctx, z, u, v, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await sigma.verifyDlog(ctx, u, v, proof);
    expect(valid).toBe(true);
  });
});


describe('dlog proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await sigma.proveDlog(ctx, z, u, v)

    // Tamper response
    proof.response = await ctx.randomScalar();

    const valid = await sigma.verifyDlog(ctx, u, v, proof);
    expect(valid).toBe(false);
  });
});


describe('dlog proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await sigma.proveDlog(ctx, z, u, v)

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await sigma.verifyDlog(ctx, u, v, proof);
    expect(valid).toBe(false);
  });
});


describe('ddh proof success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);
    const { z, ddh: { u, v, w } } = await helpers.createDDH(ctx);

    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('ddh proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    const { z, ddh: { u, v, w } } = await helpers.createDDH(ctx);

    const proof = await sigma.proveDDH(ctx, z, { u, v, w })

    // tamper response
    proof.response = await ctx.randomScalar();

    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('ddh proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    const { z, ddh: { u, v, w } } = await helpers.createDDH(ctx);

    const proof = await sigma.proveDDH(ctx, z, { u, v, w })

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
});
