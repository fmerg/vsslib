const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Point } from '../src/elgamal/abstract';
import { Polynomial } from '../src/lagrange';
import { Key } from '../src/key';
import { mod, modInv } from '../src/utils';
import { Combination, Permutation, PowerSet } from "js-combinatorics";

type KeyShare = {
  key: Key,
  index: number,
};

export function permutations(array: any[]): any[] {
  return [...Permutation.of(array)];
}

export function powerSet(array: any[]): any[] {
  return [...PowerSet.of(array)];
}

export function collections(array: any[]): any[] {
  let collections: any[] = [];

  powerSet(array).forEach((combination) => {
    const current = permutations(combination);
    collections = collections.concat(current);
  });

  return collections;
}


describe('demo', () => {
  test('demo 1 - with dealer', async () => {
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
    collections(shares).forEach(async (qualified: KeyShare[]) => {
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
  test('demo 2 - without dealer', async () => {
  });
});
