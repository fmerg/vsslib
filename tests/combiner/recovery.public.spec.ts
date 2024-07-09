import { recoverPublic } from 'vsslib/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing, mockPublicRecoverySetup } from '../helpers';

let { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Public point recovery', () => {
  it.each(cartesian([systems, algorithms])
  )('success - uconditioned - without nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, { algorithm });
      expect(isEqualBuffer(recovered, publicBytes)).toBe(qualifiedPackets.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, algorithms])
  )('success - uconditioned - with nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, withNonce: true
    });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, { algorithm, nonces });
      expect(isEqualBuffer(recovered, publicBytes)).toBe(qualifiedPackets.length >= threshold);
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, algorithms])
  )('success - threshold guard - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
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
  )('failure - missing nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({ ctx, shares, algorithm, withNonce: true });
    await expect(
      recoverPublic(
        ctx, packets, { algorithm, threshold, nonces: nonces.slice(0, nrShares - 1)}
      )
    ).rejects.toThrow('No nonce for index')
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged proof - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm, nrInvalid: 2 });
    await expect(recoverPublic(ctx, packets, { algorithm, threshold })).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged nonces - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2, withNonce: true
    });
    await expect(
      recoverPublic(ctx, packets, { algorithm, nonces, threshold })
    ).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('failure - accurate blaming - forged proof - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, blame: targetBlame } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2
    });
    let { recovered, blame } = await recoverPublic(
      ctx, packets, { algorithm, threshold, errorOnInvalid: false }
    );
    expect(isEqualBuffer(recovered, publicBytes)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, algorithms])
  )('failure - accurate blaming - forged nonces - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, blame: targetBlame, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2, withNonce: true
    });
    let { recovered, blame } = await recoverPublic(
      ctx, packets, { algorithm, threshold, nonces, errorOnInvalid: false }
    );
    expect(isEqualBuffer(recovered, publicBytes)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
});

