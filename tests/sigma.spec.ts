import { sigma, backend } from '../src';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { cartesian } from './helpers';

const helpers = require('./helpers');

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Fiat-Shamir - without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar } = ctx;
    const points = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const scalar1 = await sigma.fiatShamir(ctx, points, scalars, { algorithm });
    const res2 = await helpers.computeFiatShamir(ctx, points, scalars, { algorithm });
    expect(scalar1).toEqual(res2);
  });
});


describe('Fiat-Shamir - with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const nonce = await randomBytes();
    const res1 = await sigma.fiatShamir(ctx, points, scalars, { algorithm, nonce });
    const res2 = await helpers.computeFiatShamir(ctx, points, scalars, { algorithm, nonce });
    const res3 = await sigma.fiatShamir(ctx, points, scalars);
    const res4 = await sigma.fiatShamir(ctx, points, scalars, { algorithm, nonce: await randomBytes() });
    expect(res1).toEqual(res2);
    expect(res1).not.toEqual(res3);
    expect(res1).not.toEqual(res4);
  });
});


describe('Generic linear relation - success without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Generic linear relation - success with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const nonce = await ctx.randomBytes();
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation, { nonce });
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Generic linear relation - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation);
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
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Generic linear relation - failure if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation, { nonce });
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Generic linear relation - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, relation] = await helpers.createLinearRelation(ctx, { m: 5, n: 3 });
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveLinearRelation(ctx, witnesses, relation, { nonce });
    const pairs = { us: relation.us, vs: relation.vs };
    const valid = await sigma.verifyLinearRelation(ctx, pairs, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});


describe('Multiple AND Dlog - success without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs);
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Multiple AND Dlog - success with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs, { nonce });
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Multiple AND Dlog - failure if tampered proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs);
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
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Multiple AND Dlog - failure if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs, { nonce });
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Multiple AND Dlog - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const nonce = await ctx.randomBytes();
    const [witnesses, pairs] = await helpers.createAndDlogPairs(ctx, 5);
    const proof = await sigma.proveAndDlog(ctx, witnesses, pairs, { nonce });
    const valid = await sigma.verifyAndDlog(ctx, pairs, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});


describe('Eq Dlog proof success - without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs);
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('Eq Dlog proof success - with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveEqDlog(ctx, x, pairs, { nonce });
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Eq Dlog proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const proof = await sigma.proveEqDlog(ctx, x, pairs);
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
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Eq Dlog proof - failure if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveEqDlog(ctx, x, pairs, { nonce });
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('Eq Dlog proof - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, pairs] = await helpers.createEqDlogPairs(ctx, 3);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveEqDlog(ctx, x, pairs, { nonce });
    const valid = await sigma.verifyEqDlog(ctx, pairs, proof, { nonce: await ctx.randomBytes()});
    expect(valid).toBe(false);
  });
});


describe('Dlog proof - success without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v });
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(true);
  });
});


describe('Dlog proof - success with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDlog(ctx, x, { u, v }, { nonce});
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('Dlog proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const proof = await sigma.proveDlog(ctx, x, { u, v });
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
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Dlog proof - failure if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDlog(ctx, x, { u, v }, { nonce });
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('Dlog proof - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [x, { u, v }] = await helpers.createDlogPair(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDlog(ctx, x, { u, v }, { nonce });
    const valid = await sigma.verifyDlog(ctx, { u, v }, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});


describe('DDH proof - success without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('DDH proof - success with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { nonce });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof, { nonce });
    expect(valid).toBe(true);
  });
});


describe('DDH proof - failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
    const proof = await sigma.proveDDH(ctx, z, { u, v, w })
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
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
})


describe('DDH proof - failure missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { nonce });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('DDH proof - failure forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const [z, { u, v, w }] = await helpers.createDDHTuple(ctx);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveDDH(ctx, z, { u, v, w }, { nonce });
    const valid = await sigma.verifyDDH(ctx, { u, v, w }, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});


describe('Representation proof - success without nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(true);
  });
});


describe('Representation proof - success with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u }, { nonce });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof, { nonce });
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
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Representation proof - failure if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u }, { nonce });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof);
    expect(valid).toBe(false);
  });
});


describe('Representation proof - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = backend.initGroup(label);
    const h = await ctx.randomPoint();
    const [{ s, t }, { u }] = await helpers.createRepresentation(ctx, h);
    const nonce = await ctx.randomBytes();
    const proof = await sigma.proveRepresentation(ctx, { s, t }, { h, u }, { nonce });
    const valid = await sigma.verifyRepresentation(ctx, { h, u }, proof, { nonce: await ctx.randomBytes() });
    expect(valid).toBe(false);
  });
});
