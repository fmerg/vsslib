import { describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  shareSecret,
  combineSecretShares,
  combinePublicShares,
  sampleSharingPolynomial,
  interpolateSharingPolynomial,
} from 'vsslib/operations/shamir';
import {
  initBackend,
  parseScalar,
  randomSecret,
  extractPublic,
  isEqualSecret,
  isEqualPublic,
} from 'vsslib';
import { intToLeBytes } from 'vsslib/arith';
import { SecretShare, System } from 'vsslib/types';
import { resolveTestConfig } from '../environ';
import { createRawSharing } from '../helpers';
import { cartesian, partialPermutations, isEqualBuffer, each } from '../utils';
import { fixtures } from '../systems';

const { systems, nrShares, threshold } = resolveTestConfig();

const thresholdParams = [
  [1, 1], [2, 1], [2, 2], [3, 1], [3, 2], [3, 3], [4, 1], [4, 2], [4, 3], [4, 4],
  [5, 1], [5, 2], [5, 3], [5, 4], [5, 5],
];


const selectShare = (index: number, shares: SecretShare[]) => shares.filter(
  s => s.index == index
)[0];


describe('Sharing polynomial - sampling against interpolation', () => {
  each(cartesian([systems, [1, 2, 3, 5, 9]]))(
    'over %s - threshold %s', async (system, t) => {
    const ctx = initBackend(system);
    const secret = await ctx.randomScalar();
    const sampled = await sampleSharingPolynomial(ctx, t, secret);
    const interpolated = await interpolateSharingPolynomial(ctx, t, secret, []);
    for (const poly of [sampled, interpolated]) {
      assert.equal(poly.degree, t - 1);
      assert.equal(poly.evaluate(0), secret);
    }
    // Interpolating the sampled values below threshold gives back the polynomial
    const predefined: SecretShare[] = [];
    for (let index = 1; index < t; index++) {
      predefined.push({ index, value: ctx.scalarToBytes(sampled.evaluate(index)) });
    }
    const recovered = await interpolateSharingPolynomial(ctx, t, secret, predefined);
    assert.equal(recovered.equals(sampled), true);
  });
});


describe('Shamir secret sharing', () => {
  each(cartesian([systems, thresholdParams]))(
    'ok - without predefined shares - over %s - (n, t): %s', async (system, [n, t]) => {
    const ctx = initBackend(system);
    const { secret: original } = await randomSecret(ctx);
    const { secret, sharing } = await shareSecret(ctx, n, t, original);
    assert.equal(sharing.polynomial.degree, t - 1);
    assert.equal(sharing.polynomial.evaluate(0), await parseScalar(ctx, original));
    assert.equal(await isEqualSecret(ctx, sharing.getOriginalSecret(), original), true);
    assert.equal(await isEqualSecret(ctx, secret, original), true);
    assert.equal(n, sharing.nrShares);
    assert.equal(n, (await sharing.getSecretShares()).length);
    assert.equal(n, (await sharing.getPublicShares()).length);
    assert.equal(t, sharing.threshold);
    for (let index = 1; index <= sharing.nrShares; index++) {
      const { secretShare, publicShare } = await sharing.getShare(index);
      const { value: secretBytes } = secretShare;
      const { value: publicBytes } = publicShare;
      const targetPublic = await extractPublic(ctx, secretBytes);
      assert.equal(await isEqualPublic(ctx, publicBytes, targetPublic), true);
    }
  });
  each(cartesian([systems, thresholdParams]))(
    'ok - with predefined shares - over %s - (n, t): %s', async (system, [n, t]) => {
    const ctx = initBackend(system);
    const predefined: SecretShare[] = [];
    for (let i = 0; i < t; i++) {
      predefined.push({ index: i + 1, value: (await randomSecret(ctx)).secret });
    }
    const { secret: original } = await randomSecret(ctx);
    for (const nrPredefined of [0, t - 1]) {
      const { secret, sharing } = await shareSecret(
        ctx, n, t, original, predefined.slice(0, nrPredefined)
      );
      assert.equal(sharing.polynomial.degree, t - 1);
      assert.equal(sharing.polynomial.evaluate(0), await parseScalar(ctx, original));
      assert.equal(await isEqualSecret(ctx, sharing.getOriginalSecret(), original), true);
      assert.equal(await isEqualSecret(ctx, secret, original), true);
      assert.equal(n, sharing.nrShares);
      assert.equal(n, (await sharing.getSecretShares()).length);
      assert.equal(n, (await sharing.getPublicShares()).length);
      assert.equal(t, sharing.threshold);
      for (let index = 1; index <= nrPredefined; index++) {
        const { secretShare } = await sharing.getShare(index);
        assert.equal(
          await isEqualSecret(ctx, secretShare.value, selectShare(index, predefined).value), true
        );
      }
      for (let index = 1; index <= sharing.nrShares; index++) {
        const { secretShare, publicShare } = await sharing.getShare(index);
        const { value: secretBytes } = secretShare;
        const { value: publicBytes } = publicShare;
        const targetPublic = await extractPublic(ctx, secretBytes);
        assert.equal(await isEqualPublic(ctx, publicBytes, targetPublic), true);
      }
    }
  });
  each(systems)(
    'error - number of requested shares < threshold - over %s', async (system) => {
    const ctx = initBackend(system);
    await assert.rejects(shareSecret(ctx, 0, 2), /Number of shares must be at least one/);
  });
  each(systems)(
    'error - threshold parameter exceeds number of shares - over %s', async (system) => {
    const ctx = initBackend(system);
    await assert.rejects(shareSecret(ctx, 1, 2), /Threshold parameter exceeds number of shares/);
  });
  each(systems)(
    'error - threshold parameter < 1 - over %s', async (system) => {
    const ctx = initBackend(system);
    await assert.rejects(shareSecret(ctx, 1, 0), /Threshold parameter must be at least 1/);
  });
  each(systems)(
    'error - number of predefined shares >= threshold - over %s', async (system) => {
    const ctx = initBackend(system);
    const predefined = [
      { index: 1, value: intToLeBytes(BigInt(1)) },
      { index: 2, value: intToLeBytes(BigInt(2)) },
    ]
    await assert.rejects(shareSecret(ctx, 3, 2, undefined, predefined), /Number of predefined shares violates threshold/);
  });
  each(systems)(
    'error - invalid secret - over %s', async (system) => {
    const ctx = initBackend(system);
    const secret = Uint8Array.from([0]);
    await assert.rejects(shareSecret(ctx, 3, 2, secret), /Invalid scalar provided/);
  });
  each(systems)(
    'error - invalid predefined provided - over %s', async (system) => {
    const ctx = initBackend(system);
    await assert.rejects(shareSecret(ctx, 3, 2, undefined, [{ index: 1, value: Uint8Array.from([0]) }]), /Invalid scalar provided/);
  });
  each(systems)(
    'error - duplicate or non-integer predefined indexes - over %s', async (system) => {
    const ctx = initBackend(system);
    const value1 = (await randomSecret(ctx)).secret;
    const value2 = (await randomSecret(ctx)).secret;
    await assert.rejects(shareSecret(ctx, 4, 3, undefined, [{ index: 1, value: value1 }, { index: 1, value: value2 }]), /Indexes must be distinct/);
    await assert.rejects(shareSecret(ctx, 4, 3, undefined, [{ index: 1.5, value: value1 }]), /Index must be a positive integer/);
  });
  each(systems)(
    'error - predefined not in range - over %s', async (system) => {
    const ctx = initBackend(system);
    const value = (await randomSecret(ctx)).secret;
    await assert.rejects(shareSecret(ctx, 3, 2, undefined, [{ index: 0, value }]), /Index not in range: 0/);
    await assert.rejects(shareSecret(ctx, 3, 2, undefined, [{ index: 2, value }]), /Index not in range: 2/);
  });
  each(cartesian([systems, thresholdParams]))(
    'fixed-width scalar encoding - over %s - (n, t): %s', async (system, [n, t]) => {
    const ctx = initBackend(system);
    assert.equal(ctx.scalarBytes, fixtures[system as System].scalarBytes);
    const { secret, sharing } = await shareSecret(ctx, n, t);
    assert.equal(secret.length, ctx.scalarBytes);
    assert.deepEqual(sharing.getOriginalSecret(), secret);
    const shares = await sharing.getSecretShares();
    shares.forEach(share => assert.equal(share.value.length, ctx.scalarBytes));
    const combined = await combineSecretShares(ctx, shares.slice(0, t), t);
    assert.deepEqual(combined, secret);
  });
})


describe('Combination of secret shares (scalars)', () => {
  each(systems)('threshold guard - over %s', async (system) => {
    const { ctx, secret, secretShares } = await createRawSharing(system, nrShares, threshold);
    for (const shares of partialPermutations(secretShares, 0, threshold - 1)) {
      await assert.rejects(combineSecretShares(ctx, shares, threshold), /Insufficient number of shares/);
    }
    for (const shares of partialPermutations(secretShares, threshold, nrShares)) {
      const result = await combineSecretShares(ctx, shares, threshold);
      assert.equal(await isEqualSecret(ctx, result, secret), true);
    }
  });
  each(systems)('threshold validation - over %s', async (system) => {
    const { ctx, secretShares } = await createRawSharing(system, nrShares, threshold);
    for (const bad of [0, -1, 1.5, undefined]) {
      await assert.rejects(combineSecretShares(ctx, secretShares, bad as unknown as number), /Threshold must be a positive integer/);
    }
  });
});


describe('Combination of public shares (points)', () => {
  each(systems)('threshold guard - over %s', async (system) => {
    const { ctx, publicBytes, publicShares } = await createRawSharing(system, nrShares, threshold);
    for (const shares of partialPermutations(publicShares, 0, threshold - 1)) {
      await assert.rejects(combinePublicShares(ctx, shares, threshold), /Insufficient number of shares/);
    }
    for (const shares of partialPermutations(publicShares, threshold, nrShares)) {
      const result = await combinePublicShares(ctx, shares, threshold);
      assert.equal(isEqualBuffer(result, publicBytes), true);
    }
  });
  each(systems)('threshold validation - over %s', async (system) => {
    const { ctx, publicShares } = await createRawSharing(system, nrShares, threshold);
    for (const bad of [0, -1, 1.5, undefined]) {
      await assert.rejects(combinePublicShares(ctx, publicShares, bad as unknown as number), /Threshold must be a positive integer/);
    }
  });
});
