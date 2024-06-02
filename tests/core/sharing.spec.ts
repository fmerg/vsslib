import { Point, Group } from '../../src/backend/abstract'
import { leInt2Buff } from '../../src/arith';
import { ErrorMessages } from '../../src/errors';
import { reconstructKey, reconstructPublic } from '../../src/core';
import { PrivateShare, PublicShare } from '../../src/core';
import { partialPermutations } from '../helpers';
import { resolveTestConfig } from '../environ';
import { createKeySharingSetup, selectPrivateShare } from './helpers';
import { SharePacket } from '../../src/shamir';

const { system, nrShares, threshold } = resolveTestConfig();


describe(`Sharing, verification and reconstruction over ${system}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createKeySharingSetup({ system, nrShares, threshold });
  });

  test('Feldmann verification scheme - success', async () => {
    const { ctx, sharing, privateShares: shares } = setup;
    const { packets, commitments } = await sharing.createFeldmannPackets();
    packets.forEach(async (packet: SharePacket) => {
      const privateShare = await PrivateShare.fromFeldmannPacket(ctx, commitments, packet);
      const targetShare = selectPrivateShare(privateShare.index, shares);
      expect(await privateShare.equals(targetShare)).toBe(true);
    })
  });
  test('Feldmann verification scheme - failure', async () => {
    const { ctx, sharing, privateShares: shares } = setup;
    const { packets, commitments } = await sharing.createFeldmannPackets();
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      (await ctx.randomPoint()).toBytes()
    ];
    packets.forEach(async (packet: SharePacket) => {
      const privateShare = await PrivateShare.fromFeldmannPacket(ctx, commitments, packet);
      await expect(
        PrivateShare.fromFeldmannPacket(ctx, forgedCommitmnets, packet)
      ).rejects.toThrow(
        'Invalid share'
      );
    })
  });

  test('Pedersen verification scheme - success', async () => {
    const { ctx, sharing, privateShares: shares } = setup;
    const publicBytes = (await ctx.randomPoint()).toBytes();
    const { packets, commitments } = await sharing.createPedersenPackets(
      publicBytes
    );
    packets.forEach(async (packet: SharePacket) => {
      const privateShare = await PrivateShare.fromPedersenPacket(
        ctx,
        commitments,
        publicBytes,
        packet
      );
      const targetShare = selectPrivateShare(privateShare.index, shares);
      expect(await privateShare.equals(targetShare)).toBe(true);
    })
  });
  test('Pedersen verification scheme - failure', async () => {
    const { ctx, sharing, privateShares: shares } = setup;
    const publicBytes = (await ctx.randomPoint()).toBytes();
    const { packets, commitments } = await sharing.createPedersenPackets(
      publicBytes
    );
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      (await ctx.randomPoint()).toBytes()
    ];
    packets.forEach(async (packet: SharePacket) => {
      await expect(
        PrivateShare.fromPedersenPacket(
          ctx,
          forgedCommitmnets,
          publicBytes,
          packet,
        )
      ).rejects.toThrow(
        'Invalid share'
      );
    })
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
