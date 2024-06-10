import { Point, Group } from '../../src/backend/abstract'
import { PrivateKeyShare, PublicKeyShare } from '../../src/keys';
import { recoverKey, recoverPublicKey } from '../../src/combiner';
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

describe('Private recovery - skip threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, privateKey, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares).forEach(async (qualifiedShares) => {
      const recovered = await recoverKey(ctx, qualifiedShares);
      expect(await recovered.equals(privateKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
});
describe('Private recovery - with threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, privateKey, privateShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(recoverKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(shares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const recovered = await recoverKey(ctx, qualifiedShares, threshold);
      expect(await recovered.equals(privateKey)).toBe(true);
    });
  });
});
describe('Public recovery - skip threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, publicKey, publicShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares).forEach(async (qualifiedShares) => {
      const recovered = await recoverPublicKey(ctx, qualifiedShares);
      expect(await recovered.equals(publicKey)).toBe(
        qualifiedShares.length >= threshold
      );
    });
  });
});
describe('Public recovery - with threshold check', () => {
  it.each(systems)('over %s', async (system) => {
    const { ctx, publicKey, publicShares: shares } = await createKeySharingSetup({
      system, nrShares, threshold
    });
    partialPermutations(shares, 0, threshold - 1).forEach(async (qualifiedShares) => {
      await expect(recoverPublicKey(ctx, qualifiedShares, threshold)).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(shares, threshold, nrShares).forEach(async (qualifiedShares) => {
      const recovered = await recoverPublicKey(ctx, qualifiedShares, threshold);
      expect(await recovered.equals(publicKey)).toBe(true);
    });
  });
});
