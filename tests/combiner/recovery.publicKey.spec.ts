import { recoverPublicKey } from 'vsslib/combiner';
import { cartesian, partialPermutations, isEqualBuffer } from '../utils';
import { resolveTestConfig } from '../environ';
import { createKeySharingSetup, mockPublicKeyRecoverySetup } from '../helpers';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Public key recovery', () => {
  it.each(cartesian([systems, algorithms])
  )('success - uconditioned - without nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm
    });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm });
      expect(isEqualBuffer(recovered.asBytes(), publicKey.asBytes())).toBe(
        qualifiedPackets.length >= threshold
      );
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, algorithms])
  )('success - uconditioned - with nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm, withNonce: true
    });
    partialPermutations(packets).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm, nonces });
      expect(isEqualBuffer(recovered.asBytes(), publicKey.asBytes())).toBe(
        qualifiedPackets.length >= threshold
      );
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, algorithms])
  )('success - threshold guard - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm
    });
    partialPermutations(packets, 0, threshold - 1).forEach(async (qualifiedPackets) => {
      await expect(recoverPublicKey(ctx, qualifiedPackets, { algorithm, threshold })).rejects.toThrow(
        'Insufficient number of shares'
      );
    });
    partialPermutations(packets, threshold, nrShares).forEach(async (qualifiedPackets) => {
      let { recovered, blame } = await recoverPublicKey(ctx, qualifiedPackets, { algorithm, threshold });
      expect(isEqualBuffer(recovered.asBytes(), publicKey.asBytes())).toBe(
        qualifiedPackets.length >= threshold
      );
      expect(blame).toEqual([]);
    });
  });
  it.each(cartesian([systems, algorithms])
  )('failure - missing nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm, withNonce: true
    });
    await expect(
      recoverPublicKey(
        ctx, packets, { algorithm, threshold, nonces: nonces.slice(0, nrShares - 1)}
      )
    ).rejects.toThrow('Invalid packet with index')
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged proof - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm, nrInvalid: 2
    });
    await expect(recoverPublicKey(ctx, packets, { algorithm, threshold })).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm, nrInvalid: 2, withNonce: true
    });
    await expect(recoverPublicKey(ctx, packets, { algorithm, nonces, threshold })).rejects.toThrow(
      'Invalid packet with index'
    );
  });
  it.each(cartesian([systems, algorithms])
  )('failure - accurate blaming - forged proof - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets, blame: targetBlame } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm, nrInvalid: 2
    });
    let { recovered, blame } = await recoverPublicKey(ctx, packets, {
      algorithm, threshold, errorOnInvalid: false
    });
    expect(isEqualBuffer(recovered.asBytes(), publicKey.asBytes())).toBe(false);
    expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
  });
  it.each(cartesian([systems, algorithms])
  )('failure - accurate blaming - forged nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicKey, partialKeys } = await createKeySharingSetup(
      system, nrShares, threshold
    );
    const { packets, blame: targetBlame, nonces } = await mockPublicKeyRecoverySetup({
      ctx, partialKeys, algorithm, nrInvalid: 2, withNonce: true
    });
    let { recovered, blame } = await recoverPublicKey(ctx, packets, {
      algorithm, nonces, threshold, errorOnInvalid: false
    });
    expect(isEqualBuffer(recovered.asBytes(), publicKey.asBytes())).toBe(false);
    expect(blame.map(b => b.index).sort()).toEqual(targetBlame.sort());
  });
});

