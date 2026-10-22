import { describe, mock } from 'node:test';
import assert from 'node:assert/strict';
import {
  createSchnorrPacket,
  parseSchnorrPacket,
  recoverPublic,
} from 'vsslib/operations/recovery';
import { randomPublic, InvalidPublicShare } from 'vsslib';
import { cartesian, partialPermutations, isEqualBuffer, each } from '../utils';
import { resolveTestConfig } from '../environ';
import { createRawSharing, mockPublicRecoverySetup } from '../helpers';

const { systems, algorithms, nrShares, threshold } = resolveTestConfig();


describe('Schnorr packets', () => {
  each(cartesian([systems, algorithms])
  )('roundtrip - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares, publicShares } = await createRawSharing(
      system, nrShares, threshold
    );
    for (const [i, share] of secretShares.entries()) {
      const packet = await createSchnorrPacket(ctx, share, { algorithm });
      const parsed = await parseSchnorrPacket(ctx, packet, { algorithm });
      assert.equal(parsed.index, share.index);
      assert.equal(isEqualBuffer(parsed.value, publicShares[i].value), true);
    }
  });
  each(cartesian([systems, algorithms])
  )('tampered packets are rejected - over %s/%s', async (system, algorithm) => {
    // The proof covers both the public share and its index
    const { ctx, secretShares } = await createRawSharing(system, nrShares, threshold);
    const packet = await createSchnorrPacket(ctx, secretShares[0], { algorithm });
    const tampered = [
      { ...packet, value: await randomPublic(ctx) },
      { ...packet, index: packet.index + 1 },
    ];
    for (const forged of tampered) {
      await assert.rejects(parseSchnorrPacket(ctx, forged, { algorithm }), InvalidPublicShare);
    }
  });
});


describe('Public point recovery', () => {
  each(systems)('parses each public share once - over %s', async (system) => {
    // The proofs parse points of their own, which are not counted
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({
      ctx, shares, nrInvalid: nrShares - threshold
    });
    const parse = mock.method(ctx, 'parsePoint');
    try {
      const { recovered } = await recoverPublic(ctx, packets, threshold, { errorOnInvalid: false });
      assert.equal(isEqualBuffer(recovered, publicBytes), true);
      for (const packet of packets) {
        const calls = parse.mock.calls.filter(call => isEqualBuffer(call.arguments[0], packet.value));
        assert.equal(calls.length, 1);
      }
    } finally {
      parse.mock.restore();
    }
  });
  each(cartesian([systems, algorithms])
  )('success - without nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    for (const qualifiedPackets of partialPermutations(packets, threshold, nrShares)) {
      const { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, threshold, { algorithm });
      assert.equal(isEqualBuffer(recovered, publicBytes), true);
      assert.deepEqual(blame, []);
    }
  });
  each(cartesian([systems, algorithms])
  )('success - with nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, withNonce: true
    });
    for (const qualifiedPackets of partialPermutations(packets, threshold, nrShares)) {
      const { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, threshold, { algorithm, nonces });
      assert.equal(isEqualBuffer(recovered, publicBytes), true);
      assert.deepEqual(blame, []);
    }
  });
  each(cartesian([systems, algorithms])
  )('success - threshold guard - over %s/%s', async (system, algorithm) => {
    const { ctx, publicBytes, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    for (const qualifiedPackets of partialPermutations(packets, 0, threshold - 1)) {
      await assert.rejects(recoverPublic(ctx, qualifiedPackets, threshold, { algorithm }), /Insufficient number of shares/);
    }
    for (const qualifiedPackets of partialPermutations(packets, threshold, nrShares)) {
      const { recovered, blame } = await recoverPublic(ctx, qualifiedPackets, threshold, { algorithm });
      assert.equal(isEqualBuffer(recovered, publicBytes), true);
      assert.deepEqual(blame, []);
    }
  });
  each(cartesian([systems, algorithms])
  )('failure - missing nonce - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({ ctx, shares, algorithm, withNonce: true });
    delete nonces[1];
    await assert.rejects(recoverPublic(ctx, packets, threshold, { algorithm, nonces }), /Invalid packet with index/)
  });
  each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged proof - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm, nrInvalid: 2 });
    await assert.rejects(recoverPublic(ctx, packets, threshold, { algorithm }), /Invalid packet with index/);
  });
  each(cartesian([systems, algorithms])
  )('failure - error on invalid - forged nonces - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(
      system, nrShares, threshold
    );
    const { packets, nonces } = await mockPublicRecoverySetup({
      ctx, shares, algorithm, nrInvalid: 2, withNonce: true
    });
    await assert.rejects(recoverPublic(ctx, packets, threshold, { algorithm, nonces }), /Invalid packet with index/);
  });
  each(cartesian([systems, algorithms])
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
      assert.equal(isEqualBuffer(recovered, publicBytes), true);
      assert.deepEqual(blame.map(b => b.index).sort(), targetBlame.sort());
    }
  });
  each(cartesian([systems, algorithms])
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
      assert.equal(isEqualBuffer(recovered, publicBytes), true);
      assert.deepEqual(blame.map(b => b.index).sort(), targetBlame.sort());
    } else {
      await assert.rejects(recovery, /Insufficient number of valid shares/);
    }
  });
  each(cartesian([systems, algorithms])
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
      assert.equal(isEqualBuffer(recovered, publicBytes), true);
      assert.deepEqual(blame.map(b => b.index).sort(), targetBlame.sort());
    } else {
      await assert.rejects(recovery, /Insufficient number of valid shares/);
    }
  });
  each(cartesian([systems, algorithms])
  )('failure - too few valid shares - over %s/%s', async (system, algorithm) => {
    // With errorOnInvalid false, blamed packets are dropped; interpolating the
    // remaining fewer than threshold shares would give a wrong public
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    const qualified = packets.slice(0, threshold);
    qualified[0] = { ...qualified[0], value: await randomPublic(ctx) };
    await assert.rejects(recoverPublic(ctx, qualified, threshold, { algorithm, errorOnInvalid: false }), /Insufficient number of valid shares/);
  });
  each(cartesian([systems, algorithms])
  )('failure - threshold validation - over %s/%s', async (system, algorithm) => {
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares, algorithm });
    for (const bad of [0, -1, 1.5, undefined]) {
      await assert.rejects(recoverPublic(ctx, packets, bad as unknown as number, { algorithm }), /Threshold must be a positive integer/);
    }
  });
});
