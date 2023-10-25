const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Point } from '../src/elgamal/abstract';
import { Polynomial } from '../src/lagrange';
import { KeyShare, DecryptorShare } from '../src/shamir';
import { Key } from '../src/key';
import { mod, modInv } from '../src/utils';
import { partialPermutations } from './helpers';


describe('demo', () => {
  test('demo 1 - sharing with dealer', async () => {
    const label = 'ed25519';

    // Setup from (t, n)
    // TODO: Assert t <= n
    const n = 5;
    const t = 3;
    const ctx = elgamal.initCrypto(label);
    const { order } = ctx;
    const degree = t - 1;
    const poly = await Polynomial.random({ degree, order });
    const key = new Key(ctx, poly.coeffs[0]);
    // Compute commitments
    const commitments: Point[] = [];
    for (let i = 0; i < t; i++) {
      const comm = await ctx.operate(poly.coeffs[i], ctx.generator);
      commitments.push(comm);
    }
    // Compute key shares
    const shares: KeyShare[] = [];
    for (let i = 1; i <= n; i++) {
      const key = new Key(ctx, poly.evaluate(i));
      const index = i;
      shares.push({
        key,
        index,
      });
    }
    const setup = { n, t, key, poly, shares, commitments };
    expect(setup.n).toEqual(n);
    expect(setup.t).toEqual(t);
    expect(setup.shares.length).toEqual(n);
    expect(setup.poly.degree).toEqual(t - 1);
    expect(commitments.length).toEqual(t);

    // Verify computation of each private share
    shares.forEach(async (share) => {
      const { key, index: i } = share;
      const target = await ctx.operate(key.secret, ctx.generator);
      let acc = ctx.neutral;
      for (let j = 0; j < commitments.length; j++) {
        const curr = await ctx.operate(mod(BigInt(i ** j), ctx.order), commitments[j]);
        acc = await ctx.combine(acc, curr);
      }
      expect(await acc.isEqual(target)).toBe(true);
    });

    // Reconstruct key for each combination of involved parties
    partialPermutations(shares).forEach(async (qualified: KeyShare[]) => {
      const { order } = ctx;
      const qualifiedIndexes = qualified.map(share => share.index);
      let secret = BigInt(0);
      qualified.forEach(async share => {
        // Compute lambdai
        const sharei = share.key.secret;
        let lambdai = BigInt(1);
        const i = share.index;
        qualifiedIndexes.forEach(j => {
          if (i != j) {
            const curr = mod(BigInt(j) * modInv(BigInt(j - i), order), order);
            lambdai = mod(lambdai * curr, order);
          }
        });
        secret = mod(secret + mod(sharei * lambdai, order), order);
      });
      const reconstructed = new Key(ctx, secret);
      // Private key correctly reconstructed IFF >= t parties are involved
      expect(await reconstructed.isEqual(key)).toBe(qualified.length >= t);
    });
  });
  test('demo 2 - sharing without dealer', async () => {
  });
  test('demo 3 - threshold decryption', async () => {
    const label = 'ed25519';

    // Setup from (t, n)
    // TODO: Assert t <= n
    const n = 3;
    const t = 2;
    const ctx = elgamal.initCrypto(label);
    const { order } = ctx;
    const degree = t - 1;
    const poly = await Polynomial.random({ degree, order });
    const key = new Key(ctx, poly.coeffs[0]);
    // Compute commitments
    const commitments: Point[] = [];
    for (let i = 0; i < t; i++) {
      const comm = await ctx.operate(poly.coeffs[i], ctx.generator);
      commitments.push(comm);
    }
    // Compute key shares
    const shares: KeyShare[] = [];
    for (let i = 1; i <= n; i++) {
      const key = new Key(ctx, poly.evaluate(i));
      const index = i;
      shares.push({
        key,
        index,
      });
    }
    const setup = { n, t, key, poly, shares, commitments };

    // Encrypt something with respect to the combined public key
    const message = await ctx.randomPoint();
    const pub = (await key.extractPublic()).point;
    const { ciphertext, decryptor: _decryptor } = await ctx.encrypt(message, pub);

    // Iterate over all combinations of involved parties
    partialPermutations(shares).forEach(async (qualified: KeyShare[]) => {
      const decryptorShares = [];
      for (const share of qualified) {
        const { index, key } = share;
        const decryptor = await ctx.operate(key.secret, ciphertext.beta);
        const proof = await ctx.proveDecryptor(ciphertext, key.secret, decryptor, { algorithm: 'sha256' });
        decryptorShares.push({
          decryptor,
          index,
          proof,
        });
      }
      // Retrieve decryptor from shares
      const qualifiedIndexes = decryptorShares.map(share => share.index);
      let decryptor = ctx.neutral;
      for (const share of decryptorShares) {
        const { index: i, decryptor: dshare, proof } = share;
        // TODO: Selection by index
        const pubi = (await shares[i - 1].key.extractPublic()).point;
        const isValid = await ctx.verifyDecryptor(dshare, ciphertext, pubi, proof);
        expect(isValid).toBe(true);
        // Compute lambdai
        let lambdai = BigInt(1);
        qualifiedIndexes.forEach(j => {
          if (i != j) {
            const curr = mod(BigInt(j) * modInv(BigInt(j - i), order), order);
            lambdai = mod(lambdai * curr, order);
          }
        });
        const curr = await ctx.operate(lambdai, dshare);
        decryptor = await ctx.combine(decryptor, curr);
      }
      // Decryptor correctly retrieved IFF >= t parties are involved
      expect(await decryptor.isEqual(_decryptor)).toBe(qualified.length >= t);
      // Decrypt with recryptor
      const plaintext = await ctx.decrypt(ciphertext, { decryptor });
      // Message correctly retrieved IFF >= t parties are involved
      expect(await plaintext.isEqual(message)).toBe(qualified.length >= t);
    });
  });
});
