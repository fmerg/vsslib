import { initGroup } from '../../src/backend';
import { Point } from '../../src/backend/abstract';
import { distributeSecret } from '../../src/dealer';
import { selectSecretShare, selectPublicShare } from '../helpers';
import { resolveTestConfig } from '../environ';
import { cartesian } from '../utils';

let { systems } = resolveTestConfig();

const thresholdParams = [
  [1, 1], [2, 1], [2, 2], [3, 1], [3, 2], [3, 3], [4, 1], [4, 2], [4, 3], [4, 4],
  [5, 1], [5, 2], [5, 3], [5, 4], [5, 5],
];


describe('Sharing parameter errors', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 1, 2, secret)).rejects.toThrow(
      'Threshold parameter exceeds number of shares'
    );
    await expect(distributeSecret(ctx, 1, 0, secret)).rejects.toThrow(
      'Threshold parameter must be at least 1'
    );
    await expect(distributeSecret(ctx, ctx.order, 2, secret, [
      [BigInt(0), BigInt(1)],
      [BigInt(1), BigInt(2)],
    ])).rejects.toThrow(
      'Number of shares violates the group order'
    );
    await expect(distributeSecret(ctx, 3, 2, secret, [
      [BigInt(0), BigInt(1)],
      [BigInt(1), BigInt(2)],
    ])).rejects.toThrow(
      'Number of predefined points violates threshold'
    );
  });
})


describe('Sharing without predefined points', () => {
  it.each(
    cartesian([systems, thresholdParams])
  )('over %s for threshold: %s', async (system, [n, t]) => {
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
      expect(await target.equals(await exp(generator, ctx.leBuff2Scalar(value)))).toBe(true);
    }
    expect(polynomial.degree).toEqual(t - 1);
    expect(polynomial.evaluate(0)).toEqual(ctx.leBuff2Scalar(secret));
    const { commitments } = await sharing.createFeldmanPackets();
    expect(commitments.length).toEqual(t);
  });
});


describe('Sharing with predefined points', () => {
  it.each(
    cartesian([systems, thresholdParams])
  )('over %s for threshold: %s', async (system, [n, t]) => {
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
      const { generator } = ctx;
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
