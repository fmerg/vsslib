import { sigma, backend } from '../src';
import { Point } from '../src/backend/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { cartesian } from './helpers';

const helpers = require('./helpers');

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('Generic linear relation - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [xs, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, xs, relation);
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Generic linear relation - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [xs, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, xs, relation);
    // Tamper response
    proof.response[0] = await ctx.randomScalar();
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Generic linear relation - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [xs, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, xs, relation);
    // Change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Multiple AND Dlog - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [xs, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, xs, pairs);
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Multiple AND Dlog - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [xs, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, xs, pairs);
    // Tamper response
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Multiple AND Dlog - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [xs, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, xs, pairs);
    // Change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Eq Dlog proof success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Eq Dlog proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs);
    // Tamper last pair
    pairs[2].v = await ctx.randomPoint();
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Eq Dlog proof failure - if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs);
    // Change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Dlog proof - success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await sigma.proveDlog(ctx, z, u, v, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await sigma.verifyDlog(ctx, u, v, proof);
    expect(valid).toBe(true);
  });
});


describe('Dlog proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const z = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(z, u);
    const proof = await sigma.proveDlog(ctx, z, u, v)
    // Tamper response
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyDlog(ctx, u, v, proof);
    expect(valid).toBe(false);
  });
});


describe('Dlog proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
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


describe('DDH proof - success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { z, ddh: { u, v, w } } = await helpers.createDDH(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('DDH proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { z, ddh: { u, v, w } } = await helpers.createDDH(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w })
    // Tamper response
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('DDH proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const { z, ddh: { u, v, w } } = await helpers.createDDH(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w })
    // Change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
})
