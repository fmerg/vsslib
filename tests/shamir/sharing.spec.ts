import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import { ErrorMessages } from '../../src/errors';
import { distributeSecret, SecretShare, PublicShare } from '../../src/shamir';
import { resolveTestConfig } from '../environ';

const selectSecretShare = (index: number, shares: SecretShare[]): SecretShare => {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share with index ${index}`);
  return selected;
}

const selectPublicShare = (index: number, shares: PublicShare[]): PublicShare => {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share with index ${index}`);
  return selected;
}

let { system } = resolveTestConfig();

const thresholdParams = [
  [1, 1], [2, 1], [2, 2], [3, 1], [3, 2], [3, 3], [4, 1], [4, 2], [4, 3], [4, 4],
  [5, 1], [5, 2], [5, 3], [5, 4], [5, 5],
];


describe(`Sharing parameter errors over ${system}`, () => {
  const ctx = initGroup(system);
  test('Threshold exceeds number of shares', async () => {
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 1, 2, secret)).rejects.toThrow(
      ErrorMessages.THRESHOLD_EXCEEDS_NR_SHARES
    );
  });
  test('Threshold is < 1', async () => {
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 1, 0, secret)).rejects.toThrow(
      ErrorMessages.THRESHOLD_BELOW_ONE
    );
  });
  test('Number of shares violates group order', async () => {
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, ctx.order, 2, secret, [
      [BigInt(0), BigInt(1)],
      [BigInt(1), BigInt(2)],
    ])).rejects.toThrow(
      ErrorMessages.NR_SHARES_VIOLATES_ORDER
    );
  });
  test('Number of predefined points violates threshold', async () => {
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 3, 2, secret, [
      [BigInt(0), BigInt(1)],
      [BigInt(1), BigInt(2)],
    ])).rejects.toThrow(
      ErrorMessages.NR_PREDEFINED_VIOLATES_THRESHOLD
    );
  });
})


describe(`Sharing without predefined points over ${system}`, () => {
  it.each(thresholdParams)('(n, t) = (%s, %s)', async (n, t) => {
    const ctx = initGroup(system);
    const secret = await ctx.randomSecret();
    const sharing = await distributeSecret(ctx, n, t, secret);
    const { nrShares, threshold, polynomial } = sharing;
    expect(nrShares).toEqual(n);
    expect(threshold).toEqual(t);
    const secretShares = await sharing.getSecretShares();
    const publicShares = await sharing.getPublicShares();
    expect(secretShares.length).toEqual(n);
    expect(publicShares.length).toEqual(n);
    const { exp, generator } = ctx;
    for (let index = 1; index < nrShares; index++) {
      const { value } = selectSecretShare(index, secretShares);
      const { value: targetBytes } = selectPublicShare(index, publicShares);
      const target = await ctx.unpackValid(targetBytes);
      expect(await target.equals(await exp(ctx.leBuff2Scalar(value), generator))).toBe(true);
    }
    expect(polynomial.degree).toEqual(t - 1);
    expect(polynomial.evaluate(0)).toEqual(ctx.leBuff2Scalar(secret));
    const { commitments } = await sharing.createFeldmanPackets();
    expect(commitments.length).toEqual(t);
  });
});


describe(`Sharing with predefined points over ${system}`, () => {
  it.each(thresholdParams)('(n, t) = (%s, %s)', async (n, t) => {
    const ctx = initGroup(system);
    const secret = await ctx.randomSecret();
    for (let nrPredefined = 1; nrPredefined < t; nrPredefined++) {
      const predefined = [];
      for (let i = 0; i < nrPredefined; i++) {
        predefined.push(await ctx.randomScalar());
      }
      const sharing = await distributeSecret(ctx, n, t, secret, predefined);
      const { nrShares, threshold, polynomial } = sharing;
      expect(nrShares).toEqual(n);
      expect(threshold).toEqual(t);
      const secretShares = await sharing.getSecretShares();
      const publicShares = await sharing.getPublicShares();
      expect(secretShares.length).toEqual(n);
      expect(publicShares.length).toEqual(n);
      for (let index = 1; index <= nrPredefined; index++) {
        const { value } = selectSecretShare(index, secretShares);
        expect(ctx.leBuff2Scalar(value)).toEqual(predefined[index - 1]);
      }
      const { exp, generator } = ctx;
      for (let index = 1; index < nrShares; index++) {
        const { value: secret } = selectSecretShare(index, secretShares);
        const { value } = selectPublicShare(index, publicShares);
        const target = await ctx.unpackValid(value);
      }
      expect(polynomial.evaluate(0)).toEqual(ctx.leBuff2Scalar(secret));
      expect(polynomial.degree).toEqual(t - 1);
      const { commitments } = await sharing.createFeldmanPackets();
      expect(commitments.length).toEqual(t);
    }
  });
});
