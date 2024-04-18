import { backend } from '../../../src';
import { BaseShare } from '../../../src/vss';
import { Point } from '../../../src/backend/abstract';
import shamir from '../../../src/core/shamir';


const thresholdParams = [
  [1, 1],
  [2, 1],
  [2, 2],
  [3, 1],
  [3, 2],
  [3, 3],
  [4, 1],
  [4, 2],
  [4, 3],
  [4, 4],
  [5, 1],
  [5, 2],
  [5, 3],
  [5, 4],
  [5, 5],
];

function selectShare<T>(index: number, shares: BaseShare<T>[]): BaseShare<T> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share with index ${index}`);
  return selected;
}


describe('Sharing parameter errors', () => {
  const ctx = backend.initGroup('ed25519');
  test('Threshold exceeds number of shares', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir(ctx).distribute(secret, 1, 2)).rejects.toThrow(
      'Threshold exceeds number of shares'
    );
  });
  test('Threshold is < 1', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir(ctx).distribute(secret, 1, 0)).rejects.toThrow(
      'Threshold must be >= 1'
    );
  });
  test('Number of predefined shares exceeds threshold', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir(ctx).distribute(secret, 3, 2, [
      [BigInt(0), BigInt(1)],
      [BigInt(1), BigInt(2)],
    ])).rejects.toThrow(
      'Number of given shares exceeds threshold'
    );
  });
})


describe('Sharing without predefined shares', () => {
  it.each(thresholdParams)('(n, t) = (%s, %s)', async (n, t) => {
    const label = 'ed25519';
    const ctx = backend.initGroup(label);
    const secret = await ctx.randomScalar();
    const sharing = await shamir(ctx).distribute(secret, n, t);
    const { nrShares, threshold, polynomial } = sharing;
    expect(nrShares).toEqual(n);
    expect(threshold).toEqual(t);
    const secretShares = await sharing.getSecretShares();
    const publicShares = await sharing.getPublicShares();
    expect(secretShares.length).toEqual(n);
    expect(publicShares.length).toEqual(n);
    const { operate, generator } = ctx;
    for (let index = 1; index < nrShares; index++) {
      const { value: secret } = selectShare(index, secretShares);
      const { value: pub } = selectShare(index, publicShares);
      expect(await (pub as Point).equals(await operate(secret, generator))).toBe(true);
    }
    expect(polynomial.degree).toEqual(t - 1);
    expect(polynomial.evaluate(0)).toEqual(secret);
    const { commitments } = await sharing.getFeldmann();
    expect(commitments.length).toEqual(t);
  });
});


describe('Sharing with predefined shares', () => {
  it.each(thresholdParams)('(n, t) = (%s, %s)', async (n, t) => {
    const label = 'ed25519';
    const ctx = backend.initGroup(label);
    const secret = await ctx.randomScalar();
    for (let nrGivenShares = 1; nrGivenShares < t; nrGivenShares++) {
      const givenShares = [];
      for (let i = 0; i < nrGivenShares; i++) {
        givenShares.push(await ctx.randomScalar());
      }
      const sharing = await shamir(ctx).distribute(secret, n, t, givenShares);
      const { nrShares, threshold, polynomial } = sharing;
      expect(nrShares).toEqual(n);
      expect(threshold).toEqual(t);
      const secretShares = await sharing.getSecretShares();
      const publicShares = await sharing.getPublicShares();
      expect(secretShares.length).toEqual(n);
      expect(publicShares.length).toEqual(n);
      expect(polynomial.evaluate(0)).toEqual(secret);
      for (let index = 1; index <= nrGivenShares; index++) {
        const { value } = selectShare(index, secretShares);
        expect(value).toEqual(givenShares[index - 1]);
      }
      const { operate, generator } = ctx;
      for (let index = 1; index < nrShares; index++) {
        const { value: secret } = selectShare(index, secretShares);
        const { value: pub } = selectShare(index, publicShares);
        expect(await (pub as Point).equals(await operate(secret, generator))).toBe(true);
      }
      expect(polynomial.evaluate(0)).toEqual(secret);
      expect(polynomial.degree).toEqual(t - 1);
      const { commitments } = await sharing.getFeldmann();
      expect(commitments.length).toEqual(t);
    }
  });
});
