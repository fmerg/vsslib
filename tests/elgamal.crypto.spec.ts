import { CryptoSystem } from '../src/elgamal/crypto';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { Algorithm } from '../src/types';
import { leInt2Buff, leBuff2Int } from '../src/utils';
import { DlogPair, DDHTuple } from '../src/elgamal/crypto';
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
      [fixedBuff, pointsBuff, scalarsBuff].reduce(
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


/** Helper for creating DDH-tuples */
const createDDH = async (ctx: CryptoSystem, dlog?: bigint): Promise<{ dlog: bigint, ddh: DDHTuple }> => {
  dlog = dlog || await ctx.randomScalar();

  const u = await ctx.randomPoint();
  const v = await ctx.operate(dlog, ctx.generator);
  const w = await ctx.operate(dlog, u);

  return { dlog, ddh: { u, v, w } };
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
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verify_AND_Dlog(pairs, proof);
    expect(valid).toBe(true);
  });
});


describe('multiple AND dlog proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const dlog = await ctx.randomScalar();
    const pairs = await createDlogPairs(ctx, dlog, 3);
    const proof = await ctx.prove_AND_Dlog(dlog, pairs, Algorithms.DEFAULT);

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
    const proof = await ctx.prove_AND_Dlog(dlog, pairs, Algorithms.DEFAULT);

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
    const proof = await ctx.proveDlog(dlog, { u, v }, algorithm);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

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
    const proof = await ctx.proveDlog(dlog, { u, v }, Algorithms.DEFAULT);

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
    const proof = await ctx.proveDlog(dlog, { u, v }, Algorithms.DEFAULT);

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
    const { dlog, ddh: { u, v, w } } = await createDDH(ctx);

    const proof = await ctx.proveDDH(dlog, { u, v, w }, algorithm);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(true);
  });
});


describe('ddh proof failure if tampered', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    const { dlog, ddh: { u, v, w } } = await createDDH(ctx);

    const proof = await ctx.proveDDH(dlog, { u, v, w }, Algorithms.DEFAULT);

    // tamper response
    proof.response = await ctx.randomScalar();

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('ddh proof failure if wrong algorithm', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    const { dlog, ddh: { u, v, w } } = await createDDH(ctx);

    const proof = await ctx.proveDDH(dlog, { u, v, w }, Algorithms.DEFAULT);

    // change hash algorithm
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;

    const valid = await ctx.verifyDDH({ u, v, w }, proof);
    expect(valid).toBe(false);
  });
});


describe('encryption - decryption with secret key', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const plaintext = await ctx.decrypt(ciphertext, { secret });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with secret key failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const forged = await ctx.randomScalar();
    const plaintext = await ctx.decrypt(ciphertext, { secret: forged });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - decryption with decryptor', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const plaintext = await ctx.decrypt(ciphertext, { decryptor });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with decryptor failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const forged = await ctx.randomPoint();
    const plaintext = await ctx.decrypt(ciphertext, { decryptor: forged });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - decryption with randomness', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const plaintext = await ctx.decrypt(ciphertext, { randomness, pub });
    expect(await plaintext.isEqual(message)).toBe(true);
  });
});


describe('encryption - decryption with randomness failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness, decryptor } = await ctx.encrypt(message, pub);

    const forged = await ctx.randomScalar();
    const plaintext = await ctx.decrypt(ciphertext, { randomness: forged, pub });
    expect(await plaintext.isEqual(message)).toBe(false);
  });
});


describe('encryption - proof of encryption', () => {
  it.each(cartesian(__labels, __algorithms))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveEncryption(ciphertext, randomness, algorithm);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyEncryption(ciphertext, proof);
    expect(valid).toBe(true);
  });
});


describe('encryption - proof of encryption failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, randomness } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveEncryption(ciphertext, randomness);

    // Tamper ciphertext
    ciphertext.beta = await ctx.randomPoint();

    const valid = await ctx.verifyEncryption(ciphertext, proof);
    expect(valid).toBe(false);
  });
});


describe('encryption - proof of decryptor', () => {
  it.each(cartesian(__labels, __algorithms))('over %s/%s', async (label, algorithm) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveDecryptor(ciphertext, secret, decryptor, algorithm);
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT);

    const valid = await ctx.verifyDecryptor(decryptor, ciphertext, pub, proof);
    expect(valid).toBe(true);
  });
});


describe('encryption - proof of decryptor failure', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);

    const secret = await ctx.randomScalar();
    const pub = await ctx.operate(secret, ctx.generator);

    const message = await ctx.randomPoint();
    const { ciphertext, decryptor } = await ctx.encrypt(message, pub);
    const proof = await ctx.proveDecryptor(ciphertext, secret, decryptor);

    const forged = await ctx.randomPoint();
    const valid = await ctx.verifyDecryptor(forged, ciphertext, pub, proof);
    expect(valid).toBe(false);
  });
});
