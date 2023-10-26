const elgamal = require('../src/elgamal');
const shamir = require('../src/shamir');
import { Messages } from '../src/shamir/enums';


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


describe('setup errors', () => {
  const ctx = elgamal.initCrypto('ed25519');
  test('Threshold exceeds number of shares', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir.shareSecret(ctx, secret, 1, 2)).rejects.toThrow(
      Messages.THRESHOLD_EXCEEDS_NR_SHARES
    );
  });
  test('Threshold is < 1', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir.shareSecret(ctx, secret, 1, 0)).rejects.toThrow(
      Messages.THRESHOLD_MUST_BE_GE_ONE
    );
  });
  test('Number of given shares exceeds threshold', async () => {
    const secret = await ctx.randomScalar();
    await expect(shamir.shareSecret(ctx, secret, 3, 2, [
      [BigInt(0), BigInt(1)],
      [BigInt(1), BigInt(2)],
    ])).rejects.toThrow(
      Messages.NR_GIVEN_SHARES_GT_THRESHOLD
    );
  });
})


describe('setup without predefined shares', () => {
  it.each(thresholdParams)('n: %s, t: %s', async (n, t) => {
    const label = 'ed25519';
    const ctx = elgamal.initCrypto(label);
    const secret = await ctx.randomScalar();
    const { threshold, shares, polynomial, commitments } = await shamir.shareSecret(ctx, secret, n, t);
    expect(threshold).toEqual(t);
    expect(shares.length).toEqual(n);
    expect(polynomial.degree).toEqual(t - 1);
    expect(polynomial.evaluate(0)).toEqual(secret);
    expect(commitments.length).toEqual(t);
  });
});


describe('setup with predefined shares', () => {
  it.each(thresholdParams)('n: %s, t: %s', async (n, t) => {
    const label = 'ed25519';
    const ctx = elgamal.initCrypto(label);
    const secret = await ctx.randomScalar();
    for (let nrGivenShares = 1; nrGivenShares < t; nrGivenShares++) {
      const givenShares = [];
      for (let i = 0; i < nrGivenShares; i++) {
        givenShares.push(await ctx.randomScalar());
      }
      const { threshold, shares, polynomial, commitments } = await shamir.shareSecret(
        ctx, secret, n, t, givenShares
      );
      expect(threshold).toEqual(t);
      expect(shares.length).toEqual(n);
      expect(polynomial.evaluate(0)).toEqual(secret);
      for (let index = 1; index <= nrGivenShares; index++) {
        const { value } = shamir.selectShare(index, shares);
        expect(value).toEqual(givenShares[index - 1]);
      }
      expect(polynomial.evaluate(0)).toEqual(secret);
      expect(polynomial.degree).toEqual(t - 1);
      expect(commitments.length).toEqual(t);
    }
  });
});
