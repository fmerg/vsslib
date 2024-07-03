import { initBackend } from 'vsslib/backend';
import { leInt2Buff } from 'vsslib/arith';
import { generateSecret, extractPublic, isEqualSecret, isEqualPublic } from 'vsslib';
import { distributeSecret } from 'vsslib/dealer';
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
    const { secret: original } = await generateSecret(ctx);
    const { secret, sharing } = await distributeSecret(ctx, n, t, original);
    expect(sharing.polynomial.degree).toEqual(t - 1);
    expect(sharing.polynomial.evaluate(0)).toEqual(ctx.leBuff2Scalar(original));
    expect(await isEqualSecret(ctx, secret, original)).toBe(true);
    expect(n).toEqual(sharing.nrShares);
    expect(n).toEqual((await sharing.getSecretShares()).length);
    expect(n).toEqual((await sharing.getPublicShares()).length);
    expect(t).toEqual(sharing.threshold);
    expect(t).toEqual((await sharing.createFeldmanPackets()).commitments.length);
    for (let index = 1; index <= sharing.nrShares; index++) {
      const { secretShare, publicShare } = await sharing.getShare(index);
      const { value: secretBytes } = secretShare;
      const { value: publicBytes } = publicShare;
      const targetPublic = await extractPublic(ctx, secretBytes);
      expect(await isEqualPublic(ctx, publicBytes, targetPublic)).toBe(true);
    }
  });
  it.each(cartesian([systems, thresholdParams]))(
    'ok - with predefined shares - over %s - (n, t): %s', async (system, [n, t]) => {
    const ctx = initBackend(system);
    const predefined: Uint8Array[] = [];
    for (let i = 0; i < t; i++) {
      predefined.push((await generateSecret(ctx)).secret);
    }
    const { secret: original } = await generateSecret(ctx);
    [0, t - 1].forEach(async (nrPredefined) => {
      const { secret, sharing } = await distributeSecret(
        ctx, n, t, original, predefined.slice(0, nrPredefined)
      );
      expect(sharing.polynomial.degree).toEqual(t - 1);
      expect(sharing.polynomial.evaluate(0)).toEqual(ctx.leBuff2Scalar(original));
      expect(await isEqualSecret(ctx, secret, original)).toBe(true);
      expect(n).toEqual(sharing.nrShares);
      expect(n).toEqual((await sharing.getSecretShares()).length);
      expect(n).toEqual((await sharing.getPublicShares()).length);
      expect(t).toEqual(sharing.threshold);
      expect(t).toEqual((await sharing.createFeldmanPackets()).commitments.length);
      for (let index = 1; index <= nrPredefined; index++) {
        const { secretShare } = await sharing.getShare(index);
        expect(await isEqualSecret(ctx, secretShare.value, predefined[index - 1]));
      }
      for (let index = 1; index < sharing.nrShares; index++) {
        const { secretShare, publicShare } = await sharing.getShare(index);
        const { value: secretBytes } = secretShare;
        const { value: publicBytes } = publicShare;
        const targetPublic = await extractPublic(ctx, secretBytes);
        expect(await isEqualPublic(ctx, publicBytes, targetPublic)).toBe(true);
      }
    })
  });
  it.each(systems)(
    'error - number of requested shares < threshold - over %s', async (system) => {
    const ctx = initBackend(system);
    await expect(distributeSecret(ctx, 0, 2)).rejects.toThrow(
      'Number of shares must be at least one'
    );
  });
  it.each(systems)(
    'error - threshold parameter exceeds number of shares - over %s', async (system) => {
    const ctx = initBackend(system);
    await expect(distributeSecret(ctx, 1, 2)).rejects.toThrow(
      'Threshold parameter exceeds number of shares'
    );
  });
  it.each(systems)(
    'error - threshold parameter < 1 - over %s', async (system) => {
    const ctx = initBackend(system);
    await expect(distributeSecret(ctx, 1, 0)).rejects.toThrow(
      'Threshold parameter must be at least 1'
    );
  });
  it.each(systems)(
    'error - number of predefined shares >= threshold - over %s', async (system) => {
    const ctx = initBackend(system);
    const predefined = [leInt2Buff(BigInt(1)), leInt2Buff(BigInt(2))];
    await expect(distributeSecret(ctx, 3, 2, undefined, predefined)).rejects.toThrow(
      'Number of predefined shares violates threshold'
    );
  });
})


