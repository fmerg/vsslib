import { recoverPublicKey } from 'vsslib/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing, mockPublicRecoverySetup } from '../helpers';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Public key recovery', () => {
  it.each(cartesian([systems, algorithms])
  )('success - uconditioned - without nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm });
      expect(isEqualBuffer(recovered.asBytes(), publicBytes)).toBe(qualifiedPackets.length >= threshold);
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
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm, nonces });
      expect(isEqualBuffer(recovered.asBytes(), publicBytes)).toBe(qualifiedPackets.length >= threshold);
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
      await expect(recoverPublicKey(ctx, qualifiedPackets, { algorithm, threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(packets, threshold, nrShares).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm, threshold });
      expect(isEqualBuffer(recovered.asBytes(), publicBytes)).toBe(qualifiedPackets.length >= threshold);
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
      recoverPublicKey(
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
    await expect(recoverPublicKey(ctx, packets, { algorithm, threshold })).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2, withNonce: true
    });
    await expect(recoverPublicKey(ctx, packets, { algorithm, nonces, threshold })).rejects.toThrow(
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
    let { recovered, blame } = await recoverPublicKey(ctx, packets, {
      algorithm, threshold, errorOnInvalid: false
    });
    expect(isEqualBuffer(recovered.asBytes(), publicBytes)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, algorithms])
  )('failure - accurate blaming - forged nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secret, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, blame: targetBlame, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2, withNonce: true
    });
    let { recovered, blame } = await recoverPublicKey(ctx, packets, {
      algorithm, nonces, threshold, errorOnInvalid: false
    });
    expect(isEqualBuffer(recovered.asBytes(), publicBytes)).toBe(false);
    expect(blame.sort()).toEqual(targetBlame.sort());
  });
});

