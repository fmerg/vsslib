import { CryptoSystem } from '../src/elgamal/crypto';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';
import { DDHTuple } from '../src/elgamal/crypto';
import { cartesian, computeFiatShamir, createDlogPairs, createDDH } from './helpers';

const elgamal = require('../src/elgamal');
const backend = require('../src/elgamal/backend');


const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('fiat-shamir heuristic', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);
    const scalars = [
      await ctx.randomScalar(),
      await ctx.randomScalar(),
    ];
    const points = [
      await ctx.randomPoint(),
      await ctx.randomPoint(),
      await ctx.randomPoint(),
    ]
    const result = await ctx.fiatShamir(points, scalars, { algorithm });
    expect(result).toEqual(await computeFiatShamir(ctx, points, scalars, algorithm));
  });
});


describe('multiple AND dlog proof success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const pairs = await createDlogPairs(ctx, z, 3);
    const proof = await ctx.proveEqDlog(z, pairs, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyEqDlog(pairs, proof);
    expect(valid).toBe(true);
  });
});
 
 
describe('multiple AND dlog proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const pairs = await createDlogPairs(ctx, z, 3);
    const proof = await ctx.proveEqDlog(z, pairs);

    // Tamper last pair
    pairs[2].v = await ctx.randomPoint();

    const valid = await ctx.verifyEqDlog(pairs, proof);
    expect(valid).toBe(false);
  });
});
 
 
describe('multiple AND dlog proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const pairs = await createDlogPairs(ctx, z, 3);
    const proof = await ctx.proveEqDlog(z, pairs);

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await ctx.verifyEqDlog(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('single z proof success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await ctx.proveDlog(z, u, v, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyDlog(u, v, proof);
    expect(valid).toBe(true);
  });
});


describe('single z proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await ctx.proveDlog(z, u, v)

    // tamper response
    proof.response = await ctx.randomScalar();

    const valid = await ctx.verifyDlog(u, v, proof);
    expect(valid).toBe(false);
  });
});


describe('single z proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await ctx.proveDlog(z, u, v)

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await ctx.verifyDlog(u, v, proof);
    expect(valid).toBe(false);
  });
});


describe('ddh proof success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);
    const { z, ddh: { u, v, w } } = await createDDH(ctx);

    const proof = await ctx.proveDDH(z, { u, v, w }, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('ddh proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    const { z, ddh: { u, v, w } } = await createDDH(ctx);

    const proof = await ctx.proveDDH(z, { u, v, w })

    // tamper response
    proof.response = await ctx.randomScalar();

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('ddh proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    const { z, ddh: { u, v, w } } = await createDDH(ctx);

    const proof = await ctx.proveDDH(z, { u, v, w })

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});
