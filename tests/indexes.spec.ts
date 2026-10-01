import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import {
  combineSecretShares,
  combinePublicShares,
  recoverPublic,
  parseSchnorrPacket,
  createSchnorrPacket,
  verifyFeldmanCommitments,
  createFeldmanPackets,
  computeLambda,
  computeLambdas,
  InvalidInput,
  InvalidPublicShare,
} from 'vsslib';
import { resolveTestConfig } from './environ';
import { computeLambdaNaive } from 'vsslib/lagrange';
import { createRawSharing, mockPublicRecoverySetup } from './helpers';

const { systems, nrShares, threshold } = resolveTestConfig();

const badIndexes = [0, -1, 1.5, NaN, Infinity, 2 ** 53];


describe('Share index validation', () => {
  each(systems)('combination rejects duplicate indexes over %s', async (system) => {
    const { ctx, secretShares, publicShares } = await createRawSharing(system, nrShares, threshold);
    const secrets = [...secretShares.slice(0, threshold - 1), secretShares[0]];
    const publics = [...publicShares.slice(0, threshold - 1), publicShares[0]];
    await assert.rejects(combineSecretShares(ctx, secrets, threshold), InvalidInput);
    await assert.rejects(combinePublicShares(ctx, publics, threshold), InvalidInput);
  });
  each(systems)('combination rejects malformed indexes over %s', async (system) => {
    const { ctx, secretShares, publicShares } = await createRawSharing(system, nrShares, threshold);
    for (const index of badIndexes) {
      const secrets = [{ ...secretShares[0], index }, ...secretShares.slice(1)];
      const publics = [{ ...publicShares[0], index }, ...publicShares.slice(1)];
      await assert.rejects(combineSecretShares(ctx, secrets, threshold), /positive integer/);
      await assert.rejects(combinePublicShares(ctx, publics, threshold), /positive integer/);
    }
  });
  each(systems)('lambda rejects inconsistent indexes over %s', async (system) => {
    const { ctx } = await createRawSharing(system, nrShares, threshold);
    assert.throws(() => computeLambda(ctx, 1, [1, 2, 2]), InvalidInput);
    assert.throws(() => computeLambda(ctx, 3, [1, 2]), InvalidInput);
    assert.throws(() => computeLambda(ctx, 1.5, [1.5, 2]), InvalidInput);
    assert.throws(() => computeLambdas(ctx, [1, 2, 2]), InvalidInput);
    assert.throws(() => computeLambdas(ctx, [1.5, 2]), InvalidInput);
    assert.throws(() => computeLambdas(ctx, [0, 1]), InvalidInput);
  });
  test('lambdas reject indexes not below the group order', async () => {
    // Built-in orders exceed every safe integer; a small order stands in for a
    // custom backend, where such indexes would make inversions fail
    const ctx = { order: BigInt(7) } as unknown as Parameters<typeof computeLambdas>[0];
    assert.throws(() => computeLambdas(ctx, [7, 1]), /below the group order/);
    assert.throws(() => computeLambdas(ctx, [1, 8]), InvalidInput);
    assert.throws(() => computeLambda(ctx, 1, [1, 8]), InvalidInput);
    const indexes = [1, 2, 6];
    assert.deepEqual(computeLambdas(ctx, indexes), indexes.map(index => computeLambdaNaive(ctx, index, indexes)));
    const shares = [1, 8].map(index => ({ index, value: new Uint8Array(32) }));
    await assert.rejects(combineSecretShares(ctx, shares, 2), InvalidInput);
    await assert.rejects(combinePublicShares(ctx, shares, 2), InvalidInput);
  });
  each(systems)('verification rejects malformed indexes over %s', async (system) => {
    const { ctx, sharing, secretShares } = await createRawSharing(system, nrShares, threshold);
    const { commitments } = await createFeldmanPackets(sharing);
    for (const index of badIndexes) {
      await assert.rejects(verifyFeldmanCommitments(ctx, commitments, { ...secretShares[0], index }, threshold), /positive integer/);
      await assert.rejects(createSchnorrPacket(ctx, { ...secretShares[0], index }), /positive integer/);
    }
  });
  each(systems)('recovery rejects replayed packets over %s', async (system) => {
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares });
    const replayed = [...packets.slice(0, threshold), packets[0]];
    for (const errorOnInvalid of [true, false]) {
      await assert.rejects(recoverPublic(ctx, replayed, threshold, { errorOnInvalid }), /distinct/);
    }
  });
  each(systems)('proof is bound to the index over %s', async (system) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares });
    const relabeled = { ...packets[0], index: nrShares + 1 };
    await assert.rejects(parseSchnorrPacket(ctx, relabeled), InvalidPublicShare);
    const recovery = recoverPublic(
      ctx, [relabeled, ...packets.slice(1)], threshold, { errorOnInvalid: false }
    );
    if (nrShares - 1 >= threshold) {
      const { recovered, blame } = await recovery;
      assert.deepEqual(blame, [{ value: relabeled.value, index: relabeled.index }]);
      assert.equal(Buffer.from(recovered).equals(Buffer.from(publicBytes)), true);
    } else {
      await assert.rejects(recovery, InvalidPublicShare);
    }
  });
});
