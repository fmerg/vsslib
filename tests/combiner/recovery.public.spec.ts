import { recoverPublic } from '../../src/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createSharingSetup, createPublicPackets } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Public point recovery', () => {
  it.each(cartesian([systems, algorithms])
  )('success - uconditioned - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { packets } = await createPublicPackets({ ctx, shares, algorithm });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, { algorithm });
      expect(isEqualBuffer(recovered, publicBytes)).toBe(qualifiedPackets.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, algorithms])
  )('success - threshold guard - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { packets } = await createPublicPackets({ ctx, shares, algorithm });
    partialPermutations(packets, 0, threshold - 1).forEach(async (qualifiedPackets) => {
      await expect(recoverPublic(ctx, qualifiedPackets, { algorithm, threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(packets, threshold, nrShares).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, { algorithm, threshold });
      expect(isEqualBuffer(recovered, publicBytes)).toBe(qualifiedPackets.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { invalidPackets } = await createPublicPackets({
      ctx, shares, algorithm, nrInvalidIndexes: 2
    });
    await expect(recoverPublic(ctx, invalidPackets, { algorithm, threshold })).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('failure - with blame - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createSharingSetup({
      system, nrShares, threshold
    });
    const { invalidPackets, blame: targetBlame } = await createPublicPackets({
      ctx, shares, algorithm, nrInvalidIndexes: 2
    });
    let { recovered, blame } = await recoverPublic(
      ctx, invalidPackets, { algorithm, threshold, errorOnInvalid: false }
    );
    expect(isEqualBuffer(recovered, publicBytes)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
});

