import {
  combineSecretShares,
  combinePublicShares,
  recoverPublic,
  parseSchnorrPacket,
  createSchnorrPacket,
  verifyFeldmanCommitments,
  computeLambda,
  InvalidInput,
  InvalidPublicShare,
} from 'vsslib';
import { resolveTestConfig } from './environ';
import { createRawSharing, mockPublicRecoverySetup } from './helpers';

const { systems, nrShares, threshold } = resolveTestConfig();

const badIndexes = [0, -1, 1.5, NaN, Infinity, 2 ** 53];


describe('Share index validation', () => {
  it.each(systems)('combination rejects duplicate indexes over %s', async (system) => {
    const { ctx, secretShares, publicShares } = await createRawSharing(system, nrShares, threshold);
    const secrets = [...secretShares.slice(0, threshold - 1), secretShares[0]];
    const publics = [...publicShares.slice(0, threshold - 1), publicShares[0]];
    await expect(combineSecretShares(ctx, secrets)).rejects.toThrow(InvalidInput);
    await expect(combinePublicShares(ctx, publics)).rejects.toThrow(InvalidInput);
  });
  it.each(systems)('combination rejects malformed indexes over %s', async (system) => {
    const { ctx, secretShares, publicShares } = await createRawSharing(system, nrShares, threshold);
    for (const index of badIndexes) {
      const secrets = [{ ...secretShares[0], index }, ...secretShares.slice(1)];
      const publics = [{ ...publicShares[0], index }, ...publicShares.slice(1)];
      await expect(combineSecretShares(ctx, secrets)).rejects.toThrow('positive integer');
      await expect(combinePublicShares(ctx, publics)).rejects.toThrow('positive integer');
    }
  });
  it.each(systems)('lambda rejects inconsistent indexes over %s', async (system) => {
    const { ctx } = await createRawSharing(system, nrShares, threshold);
    expect(() => computeLambda(ctx, 1, [1, 2, 2])).toThrow(InvalidInput);
    expect(() => computeLambda(ctx, 3, [1, 2])).toThrow(InvalidInput);
    expect(() => computeLambda(ctx, 1.5, [1.5, 2])).toThrow(InvalidInput);
  });
  it.each(systems)('verification rejects malformed indexes over %s', async (system) => {
    const { ctx, sharing, secretShares } = await createRawSharing(system, nrShares, threshold);
    const { commitments } = await sharing.createFeldmanPackets();
    for (const index of badIndexes) {
      await expect(
        verifyFeldmanCommitments(ctx, commitments, { ...secretShares[0], index }, threshold)
      ).rejects.toThrow('positive integer');
      await expect(
        createSchnorrPacket(ctx, { ...secretShares[0], index })
      ).rejects.toThrow('positive integer');
    }
  });
  it.each(systems)('recovery rejects replayed packets over %s', async (system) => {
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares });
    const replayed = [...packets.slice(0, threshold), packets[0]];
    for (const errorOnInvalid of [true, false]) {
      await expect(
        recoverPublic(ctx, replayed, { errorOnInvalid })
      ).rejects.toThrow('distinct');
    }
  });
  it.each(systems)('proof is bound to the index over %s', async (system) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares });
    const relabeled = { ...packets[0], index: nrShares + 1 };
    await expect(parseSchnorrPacket(ctx, relabeled)).rejects.toThrow(InvalidPublicShare);
    const { recovered, blame } = await recoverPublic(
      ctx, [relabeled, ...packets.slice(1)], { errorOnInvalid: false }
    );
    expect(blame).toEqual([{ value: relabeled.value, index: relabeled.index }]);
    expect(Buffer.from(recovered).equals(Buffer.from(publicBytes))).toBe(nrShares - 1 >= threshold);
  });
});
