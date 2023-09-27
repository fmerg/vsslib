import { CryptoSystem } from '../src/elgamal/crypto';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';
import { DlogPair } from '../src/elgamal/crypto';
import { cartesian } from './helpers';

const elgamal = require('../src/elgamal');
const backend = require('../src/elgamal/backend');
const utils = require('../src/utils');


const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


/** Helper for reproducing externally the fiat-shamir computation */
const computeFiatShamir = async (
  ctx: CryptoSystem,
  points: Point[],
  scalars: bigint[],
  algorithm: Algorithm | undefined,
): Promise<bigint> => {
  const fixedBuff = [
    leInt2Buff(ctx.modulus),
    leInt2Buff(ctx.order),
    ctx.generator.toBytes(),
  ].reduce(
    (acc: number[], curr: Uint8Array) => [...acc, ...curr], []
  )
  const pointsBuff = points.reduce(
    (acc: number[], p: Point) => [...acc, ...p.toBytes()], []
  );
  const scalarsBuff = scalars.reduce(
    (acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []
  );
  const buffer = [fixedBuff, scalarsBuff, pointsBuff].reduce(
    (acc, curr) => [...acc, ...curr], []
  );
  const digest = await utils.hash(
    new Uint8Array(
      [fixedBuff, scalarsBuff, pointsBuff].reduce(
        (acc, curr) => [...acc, ...curr], []
      )
    ),
    { algorithm }
  );
  return (leBuff2Int(digest) as bigint) % ctx.order;
}


/** Helper for creating dlog pairs with uniform logarithm */
const createDlogPairs = async (ctx: CryptoSystem, dlog: bigint, nrPairs: number): Promise<DlogPair[]> => {
  const us = [];
  for (let i = 0; i < nrPairs; i++) {
    us.push(await ctx.randomPoint());
  }

  const pairs = [];
  for (const u of us) {
    pairs.push({
      u,
      v: await ctx.operate(dlog, u),
    });
  }

  return pairs;
}


describe('crypto initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx1 = elgamal.initCrypto(label);
    const ctx2 = new CryptoSystem(backend.initGroup(label));
    expect(await ctx1.isEqual(ctx2)).toBe(true);
    expect(await ctx1.label).toEqual(label);
  });
});


describe('crypto initialization failure', () => {
  test('unsupported crypto', () => {
    const unsupported = 'unsupported';
    expect(() => elgamal.initCrypto(unsupported)).toThrow(
      `Unsupported crypto: ${unsupported}`
    );
  });
});


describe('crypto equality', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    expect(await ctx.isEqual(elgamal.initCrypto(label))).toBe(true);
    expect(await ctx.isEqual(
      elgamal.initCrypto(
        label == Systems.ED25519 ?
          Systems.ED448 :
          Systems.ED25519
      )
    )).toBe(false);
  });
});


describe('fiat-shamir heuristic', () => {
  it.each(cartesian(__labels, __algorithms))('over %s/%s', async (label, algorithm) => {
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
    const result = await ctx.fiatShamir(points, scalars, algorithm);
    expect(result).toEqual(await computeFiatShamir(ctx, points, scalars, algorithm));
  });
});


describe('multiple AND dlog proof success', () => {
  it.each(cartesian(__labels, __algorithms))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const dlog = await ctx.randomScalar();
    const pairs = await createDlogPairs(ctx, dlog, 3);
    const proof = await ctx.prove_AND_Dlog(dlog, pairs, algorithm);
    expect(proof.algorithm).toBe(algorithm || 'sha256');

    const valid = await ctx.verify_AND_Dlog(pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('multiple AND dlog proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const dlog = await ctx.randomScalar();
    const pairs = await createDlogPairs(ctx, dlog, 3);
    const proof = await ctx.prove_AND_Dlog(dlog, pairs, Algorithms.SHA256);

    // Tamper last pair
    pairs[2].v = await ctx.randomPoint();

    const valid = await ctx.verify_AND_Dlog(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('multiple AND dlog proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const dlog = await ctx.randomScalar();
    const pairs = await createDlogPairs(ctx, dlog, 3);
    const proof = await ctx.prove_AND_Dlog(dlog, pairs, Algorithms.SHA256);

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await ctx.verify_AND_Dlog(pairs, proof);
    expect(valid).toBe(false);
  });
});


describe('single dlog proof success', () => {
  it.each(cartesian(__labels, __algorithms))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const dlog = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(dlog, u);
    const proof = await ctx.proveDlog(dlog, { u, v }, Algorithms.SHA256);

    const valid = await ctx.verifyDlog({ u, v }, proof);
    expect(valid).toBe(true);
  });
});


describe('single dlog proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const dlog = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(dlog, u);
    const proof = await ctx.proveDlog(dlog, { u, v }, Algorithms.SHA256);

    // tamper response
    proof.response = await ctx.randomScalar();

    const valid = await ctx.verifyDlog({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('single dlog proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const dlog = await ctx.randomScalar();
    const u = await ctx.randomPoint();
    const v = await ctx.operate(dlog, u);
    const proof = await ctx.proveDlog(dlog, { u, v }, Algorithms.SHA256);

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await ctx.verifyDlog({ u, v }, proof);
    expect(valid).toBe(false);
  });
});


describe('ddh proof success', () => {
  it.each(cartesian(__labels, __algorithms))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const u = await ctx.randomPoint();
    const z = await ctx.randomScalar()
    const v = await ctx.operate(z, u);
    const w = await ctx.operate(z, v);
    const proof = await ctx.proveDDH(z, { u, v, w }, algorithm);

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('ddh proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const u = await ctx.randomPoint();
    const z = await ctx.randomScalar()
    const v = await ctx.operate(z, u);
    const w = await ctx.operate(z, v);
    const proof = await ctx.proveDDH(z, { u, v, w }, Algorithms.SHA256);

    // tamper response
    proof.response = await ctx.randomScalar();

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('ddh proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const u = await ctx.randomPoint();
    const z = await ctx.randomScalar()
    const v = await ctx.operate(z, u);
    const w = await ctx.operate(z, v);
    const proof = await ctx.proveDDH(z, { u, v, w }, Algorithms.SHA256);

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);

  });
});
