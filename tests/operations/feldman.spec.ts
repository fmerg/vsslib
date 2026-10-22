import { describe } from 'node:test';
import assert from 'node:assert/strict';
import { each } from '../utils';
import { createFeldmanPackets, verifyFeldmanCommitments, parseFeldmanPacket } from 'vsslib/operations/feldman';
import { initBackend, randomPublic, shareSecret } from 'vsslib';
import { resolveTestConfig } from '../environ';
import { isEqualBuffer } from '../utils';

const { systems, nrShares, threshold } = resolveTestConfig();


describe('Feldman VSS scheme', () => {
  each(systems)('success over %s', async (system) => {
    const ctx = initBackend(system);
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const secretShares = await sharing.getSecretShares();
    const { packets, commitments } = await createFeldmanPackets(sharing);
    assert.deepEqual(commitments.length, threshold);
    assert.deepEqual(packets.length, nrShares);
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
