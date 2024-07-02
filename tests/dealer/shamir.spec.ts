import { initBackend } from '../../src/backend';
import { distributeSecret } from '../../src/dealer';
import { leInt2Buff } from '../../src/arith';
import { selectSecretShare, selectPublicShare } from '../helpers';
import { resolveTestConfig } from '../environ';
import { cartesian } from '../utils';

let { systems } = resolveTestConfig();

const thresholdParams = [
  [1, 1], [2, 1], [2, 2], [3, 1], [3, 2], [3, 3], [4, 1], [4, 2], [4, 3], [4, 4],
  [5, 1], [5, 2], [5, 3], [5, 4], [5, 5],
];


describe('Shamir secret sharing', () => {
  it.each(cartesian([systems, thresholdParams]))(
    'ok - without predefined shares - over %s - (n, t): %s', async (system, [n, t]) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    const { sharing } = await distributeSecret(ctx, n, t, secret);
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
  it.each(cartesian([systems, thresholdParams]))(
    'ok - with predefined shares - over %s - (n, t): %s', async (system, [n, t]) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    for (let nrPredefined = 1; nrPredefined < t; nrPredefined++) {
      const predefined = [];
      for (let i = 0; i < nrPredefined; i++) {
        predefined.push(await ctx.randomSecret());
      }
      const { sharing } = await distributeSecret(ctx, n, t, secret, predefined);
      const { nrShares, threshold, polynomial } = sharing;
      expect(nrShares).toEqual(n);
      expect(threshold).toEqual(t);
      const secretShares = await sharing.getSecretShares();
      const publicShares = await sharing.getPublicShares();
      expect(secretShares.length).toEqual(n);
      expect(publicShares.length).toEqual(n);
      for (let index = 1; index <= nrPredefined; index++) {
        const { value } = selectSecretShare(index, secretShares);
        // TODO: isEqualScalar functionality
        expect(ctx.leBuff2Scalar(value)).toEqual(ctx.leBuff2Scalar(predefined[index - 1]));
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
  it.each(systems)(
    'error - number of requested shares < threshold - over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 0, 2, secret)).rejects.toThrow(
      'Number of shares must be at least one'
    );
  });
  it.each(systems)(
    'error - threshold parameter exceeds number of shares - over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 1, 2, secret)).rejects.toThrow(
      'Threshold parameter exceeds number of shares'
    );
  });
  it.each(systems)(
    'error - threshold parameter < 1 - over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 1, 0, secret)).rejects.toThrow(
      'Threshold parameter must be at least 1'
    );
  });
  it.each(systems)(
    'error - number of predefined shares >= threshold - over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomSecret();
    await expect(distributeSecret(ctx, 3, 2, secret, [
      leInt2Buff(BigInt(1)),
      leInt2Buff(BigInt(2)),
    ])).rejects.toThrow(
      'Number of predefined shares violates threshold'
    );
  });
})


