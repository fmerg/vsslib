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
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Generic linear relation - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
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
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
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
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs);
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Multiple AND Dlog - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs);
    // Tamper response
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Multiple AND Dlog - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs);
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
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v }, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(true);
  });
});


describe('Dlog proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v });
    // Tamper response
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Dlog proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v });
    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('DDH proof - success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('DDH proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
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
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w })
    // Change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
})


describe('Representation proof - success', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(true);
  });
});


describe('Representation proof - failure if swaped scalar factors', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s: t, t: s}, { h, u });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Representation proof - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u });
    // Tamper response
    proof.response[0] = await ctx.randomScalar();
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Representation proof - failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u });
    // Change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});
