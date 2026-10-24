import { describe, mock } from 'node:test';
import assert from 'node:assert/strict';
import { each } from './utils';
import { nizk } from 'vsslib/nizk';
import { indexToBytes } from 'vsslib/indexes';
import {
  parsePoint,
  parseSchnorrPacket,
  recoverPublic,
  derivePedersenBase,
  createPedersenPackets,
  InvalidInput,
  InvalidPublicShare,
} from 'vsslib';
import { Algorithms } from 'vsslib/enums';
import { resolveTestConfig } from './environ';
import { createRawSharing, mockPublicRecoverySetup, inheriting } from './helpers';
import { fixtures } from './systems';

const { systems, nrShares, threshold } = resolveTestConfig();

// Prime-order groups have no small-order points to test against
const cofactorSystems = systems.filter(system => fixtures[system].smallOrderPoint);


describe('Prime-order subgroup validation', () => {
  each(cofactorSystems)('small-order points are rejected over %s', async (system) => {
    const { ctx } = await createRawSharing(system, nrShares, threshold);
    // bytesToPoint decodes without validation
    const t = ctx.bytesToPoint(fixtures[system].smallOrderPoint!);
    const mixed = await ctx.operate(ctx.generator, t);
    for (const p of [t, mixed]) {
      await assert.rejects(parsePoint(ctx, p.toBytes()), /not in prime-order subgroup/);
    }
  });
  each(cofactorSystems)('public share with small-order component is rejected over %s', async (system) => {
    // The shareholder publishes y + T and retries the proof until the challenge
    // is even, so that T vanishes from the verification equation
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares });
    const { value, index } = shares[0];
    const x = await ctx.parseScalar(value);
    const g = ctx.generator;
    const y = await ctx.exp(g, x);
    const v = await ctx.operate(y, ctx.bytesToPoint(fixtures[system].smallOrderPoint!));
    const protocol = nizk(ctx, Algorithms.DEFAULT);
    const extras = [indexToBytes(index)];
    let proof;
    do {
      proof = await protocol.proveDlog(x, { u: g, v }, undefined, extras);
    } while (!(await protocol.verifyDlog({ u: g, v }, proof, undefined, extras)));
    const forged = { value: v.toBytes(), index, proof };
    await assert.rejects(parseSchnorrPacket(ctx, forged), InvalidInput);
    const tampered = [forged, ...packets.slice(1)];
    await assert.rejects(recoverPublic(ctx, tampered, threshold), /not in prime-order subgroup/);
    const recovery = recoverPublic(ctx, tampered, threshold, { errorOnInvalid: false });
    if (nrShares - 1 >= threshold) {
      const { blame } = await recovery;
      assert.deepEqual(blame.map(b => b.index), [index]);
    } else {
      await assert.rejects(recovery, /Insufficient number of valid shares/);
    }
  });
  each(systems)('trivial Pedersen bases are rejected over %s', async (system) => {
    const { ctx, sharing } = await createRawSharing(system, nrShares, threshold);
    for (const base of [ctx.neutral, ctx.generator]) {
      await assert.rejects(createPedersenPackets(sharing, base.toBytes()), /Pedersen base must be/);
    }
    assert.notEqual(await createPedersenPackets(sharing, await derivePedersenBase(ctx)), undefined);
  });
});


describe('Proof commitments without subgroup check', () => {
  each(cofactorSystems)('are parsed with small-order components over %s', async (system) => {
    const { ctx } = await createRawSharing(system, nrShares, threshold);
    const t = ctx.bytesToPoint(fixtures[system].smallOrderPoint!);
    const mixed = await ctx.operate(ctx.generator, t);
    for (const p of [t, mixed]) {
      assert.equal(await (await ctx.parseCurvePoint(p.toBytes())).equals(p), true);
    }
    // Custom backends keep the subgroup check unless they override it
    await assert.rejects(
      inheriting(ctx).parseCurvePoint(mixed.toBytes()), /not in prime-order subgroup/
    );
  });
  each(systems)('are rejected when not canonical over %s', async (system) => {
    const { ctx } = await createRawSharing(system, nrShares, threshold);
    for (const bytes of fixtures[system].nonCanonicalPoints) {
      await assert.rejects(ctx.parseCurvePoint(bytes), InvalidInput);
    }
  });
  each(cofactorSystems)('never verify with a small-order component over %s', async (system) => {
    // The prover commits to R + T instead of R. Whatever the challenge, the
    // verification equation yields R, unlike a small-order component of the
    // public share, which an even challenge cancels (see above)
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { value, index } = shares[0];
    const x = await ctx.parseScalar(value);
    const g = ctx.generator;
    const y = await ctx.exp(g, x);
    const t = ctx.bytesToPoint(fixtures[system].smallOrderPoint!);
    const protocol = nizk(ctx, Algorithms.DEFAULT);
    const extras = [indexToBytes(index)];
    // Proving raises to secrets only for its commitments
    const expSecret = ctx.expSecret;
    const forge = mock.method(ctx, 'expSecret', async (p: typeof g, s: bigint) =>
      ctx.operate(await expSecret(p, s), t)
    );
    const proofs = [];
    try {
      for (let i = 0; i < 8; i++) proofs.push(await protocol.proveDlog(x, { u: g, v: y }, undefined, extras));
    } finally {
      forge.mock.restore();
    }
    for (const proof of proofs) {
      assert.equal(await protocol.verifyDlog({ u: g, v: y }, proof, undefined, extras), false);
      await assert.rejects(
        parseSchnorrPacket(ctx, { value: y.toBytes(), index, proof }), InvalidPublicShare
      );
    }
  });
});
