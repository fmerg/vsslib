import { Group, Point } from '../../src/backend/abstract';
import { SecretShare, recoverPublic } from '../../src/shamir';
import { Algorithm } from '../../src/types';
import { cartesian, partialPermutations, isEqualBuffer, randomIndex } from '../utils';
import { resolveTestConfig } from '../environ';
import { randomDlogPair, createSharingSetup, createPublicSharePackets } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Public point recovery from packets - verification of proofs', () => {
  it.each(cartesian([systems, algorithms]))(
    'success uconditioned - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { packets } = await createPublicSharePackets({ ctx, shares, algorithm });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { result, blame } = await recoverPublic(ctx, qualifiedPackets, { algorithm });
      expect(isEqualBuffer(result, publicBytes)).toBe(qualifiedPackets.length >= threshold);
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
      await expect(recoverPublic(ctx, qualifiedPackets, { algorithm, threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    // Above threshold
    partialPermutations(packets, threshold, nrShares).forEach(async (qualifiedPackets) => {
      let { result, blame } = await recoverPublic(ctx, qualifiedPackets, { algorithm, threshold });
      expect(isEqualBuffer(result, publicBytes)).toBe(qualifiedPackets.length >= threshold);
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
    await expect(recoverPublic(ctx, invalidPackets, { algorithm, threshold })).rejects.toThrow(
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
    let { result, blame } = await recoverPublic(ctx, invalidPackets, { algorithm, threshold, errorOnInvalid: false });
    expect(isEqualBuffer(result, publicBytes)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
});

