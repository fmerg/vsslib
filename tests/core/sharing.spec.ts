import { Point, Group } from '../../src/backend/abstract'
import { ErrorMessages } from '../../src/errors';
import { reconstructKey, reconstructPublic } from '../../src/core';
import { verifyFeldmann, verifyPedersen } from '../../src/core';
import { PrivateShare, PublicShare } from '../../src/core';
import { partialPermutations } from '../helpers';
import { resolveTestConfig } from '../environ';
import { createKeyDistributionSetup } from './helpers';

const { system, nrShares, threshold } = resolveTestConfig();


describe(`Sharing, verification and reconstruction over ${system}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createKeyDistributionSetup({ system, nrShares, threshold });
  });

  test('Sharing setup parameters', async () => {
    const { privateKey, privateShares, publicShares, polynomial } = setup;
    expect(privateShares.length).toEqual(nrShares);
    expect(publicShares.length).toEqual(nrShares);
    expect(polynomial.degree).toEqual(threshold - 1);
    expect(polynomial.evaluate(0)).toEqual(privateKey.secret);
  });
  test('Feldmann verification scheme - success', async () => {
    const { ctx, sharing, privateShares } = setup;
    const { commitments } = await sharing.proveFeldmann();
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const verified = await verifyFeldmann(ctx, share, commitments);
      expect(verified).toBe(true);
    });
  });
  test('Feldmann verification scheme - failure', async () => {
    const { ctx, sharing, privateShares } = setup;
    const { commitments } = await sharing.proveFeldmann();
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1), await ctx.randomPoint()
    ];
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      await expect(
        verifyFeldmann(ctx, share, forgedCommitmnets)
      ).rejects.toThrow(ErrorMessages.INVALID_SHARE);
    });
  });
  test('Pedersen verification scheme - success', async () => {
    const { ctx, sharing, privateShares } = setup;
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const binding = bindings[share.index];
      const verified = await verifyPedersen(
        ctx, share, binding, hPub, commitments
      );
      expect(verified).toBe(true);
    });
  });
  test('Pedersen verification scheme - failure', async () => {
    const { ctx, sharing, privateShares } = setup;
    const hPub = await ctx.randomPoint();
    const { bindings, commitments } = await sharing.provePedersen(hPub);
    privateShares.forEach(async (share: PrivateShare<Point>) => {
      const forgedBinding = await ctx.randomScalar();
      await expect(
        verifyPedersen(ctx, share, forgedBinding, hPub, commitments)
      ).rejects.toThrow(ErrorMessages.INVALID_SHARE);
    });
  });
  test('Private reconstruction - skip threshold check', async () => {
    const { privateKey, privateShares, ctx } = setup;
    partialPermutations(privateShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructKey(ctx, qualifiedShares);
      expect(await reconstructed.equals(privateKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  test('Private reconstruction - with threshold check', async () => {
    const { privateKey, privateShares, ctx } = setup;
    partialPermutations(privateShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        ErrorMessages.INSUFFICIENT_NR_SHARES
      );
    });
    partialPermutations(privateShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructKey(ctx, qualifiedShares, threshold);
      expect(await reconstructed.equals(privateKey)).toBe(true);
    });
  });
  test('Public reconstruction - skip threshold check', async () => {
    const { publicKey, publicShares, ctx } = setup;
    partialPermutations(publicShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublic(ctx, qualifiedShares);
      expect(await reconstructed.equals(publicKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  test('Public reconstruction - with threshold check', async () => {
    const { publicKey, publicShares, ctx } = setup;
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructPublic(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublic(ctx, qualifiedShares, threshold);
      expect(await reconstructed.equals(publicKey)).toBe(true);
    });
  });
});
