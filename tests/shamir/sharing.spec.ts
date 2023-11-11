import { shamir, elgamal, backend } from '../../src';
import { Messages } from '../../src/shamir/enums';


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


describe('Sharing parameter errors', () => {
  const ctx = backend.initGroup('ed25519');
  test('Threshold exceeds number of shares', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir.shareSecret(ctx, secret, 1, 2)).rejects.toThrow(
      Messages.THRESHOLD_EXCEEDS_NR_SHARES
    );
  });
  test('Threshold is < 1', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir.shareSecret(ctx, secret, 1, 0)).rejects.toThrow(
      Messages.THRESHOLD_NOT_GE_ONE
    );
  });
  test('Number of predefined shares exceeds threshold', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir.shareSecret(ctx, secret, 3, 2, [
      [BigInt(0), BigInt(1)],
      [BigInt(1), BigInt(2)],
    ])).rejects.toThrow(
      Messages.NR_GIVEN_SHARES_GT_THRESHOLD
    );
  });
})


describe('Sharing without predefined shares', () => {
  it.each(thresholdParams)('(n, t) = (%s, %s)', async (n, t) => {
    const label = 'ed25519';
    const ctx = backend.initGroup(label);
    const secret = await ctx.randomScalar();
    const distribution = await shamir.shareSecret(ctx, secret, n, t);
    const { nrShares, threshold, polynomial } = distribution;
    expect(nrShares).toEqual(n);
    expect(threshold).toEqual(t);
    const secretShares = await distribution.getSecretShares();
    const publicShares = await distribution.getPublicShares();
    expect(secretShares.length).toEqual(n);
    expect(publicShares.length).toEqual(n);
    const { operate, generator } = ctx;
    for (let index = 1; index < nrShares; index++) {
      const { value: secret } = shamir.selectShare(index, secretShares);
      const { value: pub } = shamir.selectShare(index, publicShares);
      expect(await pub.isEqual(await operate(secret, generator))).toBe(true);
    }
    expect(polynomial.degree).toEqual(t - 1);
    expect(polynomial.evaluate(0)).toEqual(secret);
    const { commitments } = await distribution.getFeldmannCommitments();
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
      const distribution = await shamir.shareSecret(ctx, secret, n, t, givenShares);
      const { nrShares, threshold, polynomial } = distribution;
      expect(nrShares).toEqual(n);
      expect(threshold).toEqual(t);
      const secretShares = await distribution.getSecretShares();
      const publicShares = await distribution.getPublicShares();
      expect(secretShares.length).toEqual(n);
      expect(publicShares.length).toEqual(n);
      expect(polynomial.evaluate(0)).toEqual(secret);
      for (let index = 1; index <= nrGivenShares; index++) {
        const { value } = shamir.selectShare(index, secretShares);
        expect(value).toEqual(givenShares[index - 1]);
      }
      const { operate, generator } = ctx;
      for (let index = 1; index < nrShares; index++) {
        const { value: secret } = shamir.selectShare(index, secretShares);
        const { value: pub } = shamir.selectShare(index, publicShares);
        expect(await pub.isEqual(await operate(secret, generator))).toBe(true);
      }
      expect(polynomial.evaluate(0)).toEqual(secret);
      expect(polynomial.degree).toEqual(t - 1);
      const { commitments } = await distribution.getFeldmannCommitments();
      expect(commitments.length).toEqual(t);
    }
  });
});
