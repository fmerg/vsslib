import { initBackend } from 'vsslib/backend';
import { leInt2Buff } from 'vsslib/arith';
import { unpackScalar, randomSecret, extractPublic, isEqualSecret, isEqualPublic } from 'vsslib/secrets';
import { shareSecret, SecretShare } from 'vsslib/dealer';
import { resolveTestConfig } from './environ';
import { cartesian } from './utils';

let { systems } = resolveTestConfig();

const thresholdParams = [
  [1, 1], [2, 1], [2, 2], [3, 1], [3, 2], [3, 3], [4, 1], [4, 2], [4, 3], [4, 4],
  [5, 1], [5, 2], [5, 3], [5, 4], [5, 5],
];


export const selectShare = (index: number, shares: SecretShare[]) => shares.filter(
  s => s.index == index
)[0];


describe('Shamir secret sharing', () => {
  it.each(cartesian([systems, thresholdParams]))(
    'ok - without predefined shares - over %s - (n, t): %s', async (system, [n, t]) => {
    const ctx = initBackend(system);
    const { secret: original } = await randomSecret(ctx);
    const { secret, sharing } = await shareSecret(ctx, n, t, original);
    expect(sharing.polynomial.degree).toEqual(t - 1);
    expect(sharing.polynomial.evaluate(0)).toEqual(await unpackScalar(ctx, original));
    expect(await isEqualSecret(ctx, sharing.getOriginalSecret(), original)).toBe(true);
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
    const predefined: SecretShare[] = [];
    for (let i = 0; i < t; i++) {
      // predefined.push((await randomSecret(ctx)).secret);
      predefined.push({ index: i + 1, value: (await randomSecret(ctx)).secret });
    }
    const { secret: original } = await randomSecret(ctx);
    [0, t - 1].forEach(async (nrPredefined) => {
      const { secret, sharing } = await shareSecret(
        ctx, n, t, original, predefined.slice(0, nrPredefined)
      );
      expect(sharing.polynomial.degree).toEqual(t - 1);
      expect(sharing.polynomial.evaluate(0)).toEqual(await unpackScalar(ctx, original));
      expect(await isEqualSecret(ctx, sharing.getOriginalSecret(), original)).toBe(true);
      expect(await isEqualSecret(ctx, secret, original)).toBe(true);
      expect(n).toEqual(sharing.nrShares);
      expect(n).toEqual((await sharing.getSecretShares()).length);
      expect(n).toEqual((await sharing.getPublicShares()).length);
      expect(t).toEqual(sharing.threshold);
      expect(t).toEqual((await sharing.createFeldmanPackets()).commitments.length);
      for (let index = 1; index <= nrPredefined; index++) {
        const { secretShare } = await sharing.getShare(index);
        expect(
          await isEqualSecret(ctx, secretShare.value, selectShare(index, predefined).value)
);
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
    await expect(shareSecret(ctx, 0, 2)).rejects.toThrow(
      'Number of shares must be at least one'
    );
  });
  it.each(systems)(
    'error - threshold parameter exceeds number of shares - over %s', async (system) => {
    const ctx = initBackend(system);
    await expect(shareSecret(ctx, 1, 2)).rejects.toThrow(
      'Threshold parameter exceeds number of shares'
    );
  });
  it.each(systems)(
    'error - threshold parameter < 1 - over %s', async (system) => {
    const ctx = initBackend(system);
    await expect(shareSecret(ctx, 1, 0)).rejects.toThrow(
      'Threshold parameter must be at least 1'
    );
  });
  it.each(systems)(
    'error - number of predefined shares >= threshold - over %s', async (system) => {
    const ctx = initBackend(system);
    const predefined = [
      { index: 1, value: leInt2Buff(BigInt(1)) },
      { index: 2, value: leInt2Buff(BigInt(2)) },
    ]
    await expect(shareSecret(ctx, 3, 2, undefined, predefined)).rejects.toThrow(
      'Number of predefined shares violates threshold'
    );
  });
  it.each(systems)(
    'error - invalid secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = Uint8Array.from([0]);
    await expect(shareSecret(ctx, 3, 2, secret)).rejects.toThrow(
      'Invalid scalar provided'
    );
  });
  it.each(systems)(
    'error - invalid predefined provided - over %s', async (system) => {
    const ctx = initBackend(system);
    await expect(
      shareSecret(ctx, 3, 2, undefined, [{ index: 1, value: Uint8Array.from([0]) }])
    ).rejects.toThrow(
      'Invalid scalar provided'
    );
  });
  it.each(systems)(
    'error - predefined not in range - over %s', async (system) => {
    const ctx = initBackend(system);
    const value = (await randomSecret(ctx)).secret;
    await expect(
      shareSecret(ctx, 3, 2, undefined, [{ index: 0, value }])
    ).rejects.toThrow(
      'Index not in range: 0'
    );
    await expect(
      shareSecret(ctx, 3, 2, undefined, [{ index: 2, value }])
    ).rejects.toThrow(
      'Index not in range: 2'
    );
  });
})


