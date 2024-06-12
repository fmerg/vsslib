import { recoverPublicKey } from '../../src/combiner';
import { SecretSharePacket } from '../../src/shamir';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createSharingSetup, createPublicSharePackets } from '../helpers';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Public key recovery', () => {
  it.each(cartesian([systems, algorithms]))(
    'success uconditioned - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { packets } = await createPublicSharePackets({ ctx, shares, algorithm });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm });
      expect(isEqualBuffer(recovered.bytes, publicBytes)).toBe(qualifiedPackets.length >= threshold);
      expect(blame).toEqual([]);
    });
  });

  it.each(cartesian([systems, algorithms]))(
    'success with threshold guard - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { packets } = await createPublicSharePackets({ ctx, shares, algorithm });
    // Below threshold
    partialPermutations(packets, 0, threshold - 1).forEach(async (qualifiedPackets) => {
      await expect(recoverPublicKey(ctx, qualifiedPackets, { algorithm, threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    // Above threshold
    partialPermutations(packets, threshold, nrShares).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm, threshold });
      expect(isEqualBuffer(recovered.bytes, publicBytes)).toBe(qualifiedPackets.length >= threshold);
      expect(blame).toEqual([]);
    });
  });

  it.each(cartesian([systems, algorithms]))(
    'failure with error - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { invalidPackets } = await createPublicSharePackets({
      ctx, shares, algorithm, nrInvalidIndexes: 2
    });
    await expect(recoverPublicKey(ctx, invalidPackets, { algorithm, threshold })).rejects.toThrow(
      'Invalid packet with index'
    );
  });

  it.each(cartesian([systems, algorithms]))(
    'failure with blame - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { invalidPackets, blame: targetBlame } = await createPublicSharePackets({
      ctx, shares, algorithm, nrInvalidIndexes: 2
    });
    let { recovered, blame } = await recoverPublicKey(ctx, invalidPackets, {
      algorithm, threshold, errorOnInvalid: false
    });
    expect(isEqualBuffer(recovered.bytes, publicBytes)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
});

