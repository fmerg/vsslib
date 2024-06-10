import { Point, Group } from '../../src/backend/abstract'
import { PrivateKeyShare, PublicKeyShare } from '../../src/keys';
import { reconstructKey, reconstructPublicKey } from '../../src/combiner';
import { SecretSharePacket } from '../../src/shamir';
import { partialPermutations } from '../utils';
import { resolveTestConfig } from '../environ';
import { selectPrivateKeyShare, createKeySharingSetup } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman verification scheme - success', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    const { packets, commitments } = await sharing.createFeldmanPackets();
    packets.forEach(async (packet: SecretSharePacket) => {
      const privateShare = await PrivateKeyShare.fromFeldmanPacket(ctx, commitments, packet);
      const targetShare = selectPrivateKeyShare(privateShare.index, shares);
      expect(await privateShare.equals(targetShare)).toBe(true);
    })
  });
});
describe('Feldman verification scheme - failure', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
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
});

describe('Pedersen verification scheme - success', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
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
  })
});
describe('Pedersen verification scheme - failure', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, sharing, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
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
  })
});

describe('Private reconstruction - skip threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, privateKey, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructKey(ctx, qualifiedShares);
      expect(await reconstructed.equals(privateKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
});
describe('Private reconstruction - with threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, privateKey, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(shares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructKey(ctx, qualifiedShares, threshold);
      expect(await reconstructed.equals(privateKey)).toBe(true);
    });
  });
});
describe('Public reconstruction - skip threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, publicKey, publicShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublicKey(ctx, qualifiedShares);
      expect(await reconstructed.equals(publicKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
});
describe('Public reconstruction - with threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, publicKey, publicShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(reconstructPublicKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(shares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const reconstructed = await reconstructPublicKey(ctx, qualifiedShares, threshold);
      expect(await reconstructed.equals(publicKey)).toBe(true);
    });
  });
});
