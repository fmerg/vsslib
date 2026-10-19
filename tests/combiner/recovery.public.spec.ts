import { recoverPublic } from 'vsslib/operations/recovery';
import { randomPublic } from 'vsslib/operations/secrets';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing, mockPublicRecoverySetup } from '../helpers';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Public point recovery', () => {
  it.each(cartesian([systems, algorithms])
  )('success - without nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    for (const qualifiedPackets of partialPermutations(packets, threshold, nrShares)) {
      const { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, threshold, { algorithm });
      expect(isEqualBuffer(recovered, publicBytes)).toBe(true);
      expect(blame).toEqual([]);
    }
  });
  it.each(cartesian([systems, algorithms])
  )('success - with nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, withNonce: true
    });
    for (const qualifiedPackets of partialPermutations(packets, threshold, nrShares)) {
      const { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, threshold, { algorithm, nonces });
      expect(isEqualBuffer(recovered, publicBytes)).toBe(true);
      expect(blame).toEqual([]);
    }
  });
  it.each(cartesian([systems, algorithms])
  )('success - threshold guard - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    for (const qualifiedPackets of partialPermutations(packets, 0, threshold - 1)) {
      await expect(recoverPublic(ctx, qualifiedPackets, threshold, { algorithm })).rejects.toThrow(
        'Insufficient number of shares'
      );
    }
    for (const qualifiedPackets of partialPermutations(packets, threshold, nrShares)) {
      const { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, threshold, { algorithm });
      expect(isEqualBuffer(recovered, publicBytes)).toBe(true);
      expect(blame).toEqual([]);
    }
  });
  it.each(cartesian([systems, algorithms])
  )('failure - missing nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({ ctx, shares, algorithm, withNonce: true });
    delete nonces[1];
    await expect(
      recoverPublic(ctx, packets, threshold, { algorithm, nonces })
    ).rejects.toThrow('Invalid packet with index')
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged proof - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm, nrInvalid: 2 });
    await expect(recoverPublic(ctx, packets, threshold, { algorithm })).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged nonces - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2, withNonce: true
    });
    await expect(
      recoverPublic(ctx, packets, threshold, { algorithm, nonces })
    ).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('success - accurate blaming - enough valid shares - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    for (const withNonce of [false, true]) {
      const { packets, blame: targetBlame, nonces } = await mockPublicRecoverySetup({
        ctx, shares, algorithm, nrInvalid: nrShares - threshold, withNonce
      });
      const { recovered, blame } = await recoverPublic(
        ctx, packets, threshold, { algorithm, nonces, errorOnInvalid: false }
      );
      expect(isEqualBuffer(recovered, publicBytes)).toBe(true);
      expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
    }
  });
  it.each(cartesian([systems, algorithms])
  )('failure - accurate blaming - forged proof - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, blame: targetBlame } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2
    });
    const recovery = recoverPublic(ctx, packets, threshold, { algorithm, errorOnInvalid: false });
    if (nrShares - 2 >= threshold) {
      const { recovered, blame } = await recovery;
      expect(isEqualBuffer(recovered, publicBytes)).toBe(true);
      expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
    } else {
      await expect(recovery).rejects.toThrow('Insufficient number of valid shares');
    }
  });
  it.each(cartesian([systems, algorithms])
  )('failure - accurate blaming - forged nonces - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, blame: targetBlame, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2, withNonce: true
    });
    const recovery = recoverPublic(ctx, packets, threshold, { algorithm, nonces, errorOnInvalid: false });
    if (nrShares - 2 >= threshold) {
      const { recovered, blame } = await recovery;
      expect(isEqualBuffer(recovered, publicBytes)).toBe(true);
      expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
    } else {
      await expect(recovery).rejects.toThrow('Insufficient number of valid shares');
    }
  });
  it.each(cartesian([systems, algorithms])
  )('failure - too few valid shares - over %s/%s', async (system, algorithm) => {
    // With errorOnInvalid false, blamed packets are dropped; interpolating the
    // remaining fewer than threshold shares would give a wrong public
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    const qualified = packets.slice(0, threshold);
    qualified[0] = { ...qualified[0], value: await randomPublic(ctx) };
    await expect(
      recoverPublic(ctx, qualified, threshold, { algorithm, errorOnInvalid: false })
    ).rejects.toThrow('Insufficient number of valid shares');
  });
  it.each(cartesian([systems, algorithms])
  )('failure - threshold validation - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    for (const bad of [0, -1, 1.5, undefined]) {
      await expect(
        recoverPublic(ctx, packets, bad as unknown as number, { algorithm })
      ).rejects.toThrow('Threshold must be a positive integer');
    }
  });
});
