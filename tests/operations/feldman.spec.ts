import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { createFeldmanPackets, verifyFeldmanCommitments, parseFeldmanPacket } from 'vsslib/operations/feldman';
import { initBackend, randomPublic, shareSecret } from 'vsslib';
import { resolveTestConfig } from '../environ';
import { isEqualBuffer, each } from '../utils';
import { fixRandomScalarAt } from '../helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman VSS scheme', () => {
  each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const secretShares = await sharing.getSecretShares();
    const { packets, commitments } = await createFeldmanPackets(sharing);
    assert.equal(commitments.length, threshold);
    assert.equal(packets.length, nrShares);
    for (const share of secretShares) {
      // Check verification
      const { index } = share;
      const isValid = await verifyFeldmanCommitments(
        ctx,
        commitments,
        share,
        threshold,
      );
      assert.equal(isValid, true);
      // Check parsing
      const packet = await parseFeldmanPacket(ctx, commitments, packets[index - 1], threshold);
      assert.equal(isEqualBuffer(packet.share.value, share.value), true);
    }
  });

  each(systems)('failure over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const secretShares = await sharing.getSecretShares();
    const { packets, commitments } = await createFeldmanPackets(sharing);
    commitments[0] = await randomPublic(ctx);
    for (const share of secretShares) {
      // Check verification failure
      const verification = verifyFeldmanCommitments(
        ctx,
        commitments,
        share,
        threshold,
      );
      await assert.rejects(verification, /Invalid share/);
      // Check parsing failure
      const parsed = parseFeldmanPacket(ctx, commitments, packets[share.index - 1], threshold);
      await assert.rejects(parsed, /Invalid share/);
    }
  });
  each(systems)('commitment count must match threshold over %s', async (system) => {
    // A dealer announcing threshold t but sharing with another degree must be
    // caught: with t + 1 commitments every share verifies, yet t shares cannot
    // reconstruct the secret
    const ctx = initBackend(system);
    for (const actual of [threshold - 1, threshold + 1].filter(t => t > 0)) {
      const { sharing } = await shareSecret(ctx, nrShares + 1, actual);
      const { packets, commitments } = await createFeldmanPackets(sharing);
      for (const packet of packets) {
        await assert.rejects(parseFeldmanPacket(ctx, commitments, packet, threshold), /Invalid number of commitments/);
      }
    }
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const { packets, commitments } = await createFeldmanPackets(sharing);
    for (const bad of [0, 1.5, -1]) {
      await assert.rejects(parseFeldmanPacket(ctx, commitments, packets[0], bad), /Threshold must be a positive integer/);
    }
  });
  each(systems)('vanished top coefficient over %s', async (system) => {
    // The sharing polynomial drops to degree 1, yet the dealing keeps threshold
    // commitments, the top one neutral
    const ctx = initBackend(system);
    const secret = await ctx.generateSecret();
    const random = fixRandomScalarAt(ctx, 1);
    const { sharing } = await shareSecret(ctx, 5, 3, secret);
    random.mock.restore();
    assert.equal(sharing.polynomial.degree, 1);
    const { packets, commitments } = await createFeldmanPackets(sharing);
    assert.equal(commitments.length, 3);
    assert.equal(isEqualBuffer(commitments[2], ctx.neutral.toBytes()), true);
    for (const packet of packets) {
      assert.equal(await verifyFeldmanCommitments(ctx, commitments, packet, 3), true);
    }
  });
  each(systems)('success with large indexes over %s', async (system) => {
    // index ** j exceeds Number.MAX_SAFE_INTEGER for these parameters
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, 20, 17);
    const { packets, commitments } = await createFeldmanPackets(sharing);
    for (const packet of packets) {
      assert.equal(await verifyFeldmanCommitments(ctx, commitments, packet, 17), true);
    }
  });
})
