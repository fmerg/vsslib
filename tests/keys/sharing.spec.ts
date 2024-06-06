import { Point, Group } from '../../src/backend/abstract'
import { ErrorMessages } from '../../src/errors';
import { PrivateKeyShare, PublicKeyShare } from '../../src/keys';
import { reconstructKey, reconstructPublicKey } from '../../src/combiner';
import { SecretSharePacket } from '../../src/shamir';
import { partialPermutations } from '../utils';
import { resolveTestConfig } from '../environ';
import { createKeySharingSetup } from '../helpers';

const { system, nrShares, threshold } = resolveTestConfig();


export const selectPrivateKeyShare = (index: number, shares: PrivateKeyShare<Point>[]) =>
  shares.filter(share => share.index == index)[0];


describe(`Sharing, verification and reconstruction over ${system}`, () => {
  let setup: any;

  beforeAll(async () => {
    setup = await createKeySharingSetup({ system, nrShares, threshold });
  });

  test('Feldman verification scheme - success', async () => {
    const { ctx, sharing, privateShares: shares } = setup;
    const { packets, commitments } = await sharing.createFeldmanPackets();
    packets.forEach(async (packet: SecretSharePacket) => {
      const privateShare = await PrivateKeyShare.fromFeldmanPacket(ctx, commitments, packet);
      const targetShare = selectPrivateKeyShare(privateShare.index, shares);
      expect(await privateShare.equals(targetShare)).toBe(true);
    })
  });
  test('Feldman verification scheme - failure', async () => {
    const { ctx, sharing, privateShares: shares } = setup;
    const { packets, commitments } = await sharing.createFeldmanPackets();
    const forgedCommitmnets = [
      ...commitments.slice(0, commitments.length - 1),
      (await ctx.randomPoint()).toBytes()
    ];
    packets.forEach(async (packet: SecretSharePacket) => {
      const privateShare = await PrivateKeyShare.fromFeldmanPacket(ctx, commitments, packet);
      await expect(
        PrivateKeyShare.fromFeldmanPacket(ctx, forgedCommitmnets, packet)
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
    packets.forEach(async (packet: SecretSharePacket) => {
      const privateShare = await PrivateKeyShare.fromPedersenPacket(
        ctx,
        commitments,
        publicBytes,
        packet
      );
      const targetShare = selectPrivateKeyShare(privateShare.index, shares);
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
    packets.forEach(async (packet: SecretSharePacket) => {
      await expect(
        PrivateKeyShare.fromPedersenPacket(
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
      const reconstructed = await reconstructPublicKey(ctx, qualifiedShares);
      expect(await reconstructed.equals(publicKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
  test('Public reconstruction - with threshold check', async () => {
    const { publicKey, publicShares, ctx } = setup;
    partialPermutations(publicShares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructPublicKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(publicShares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublicKey(ctx, qualifiedShares, threshold);
      expect(await reconstructed.equals(publicKey)).toBe(true);
    });
  });
});
