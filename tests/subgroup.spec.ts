import { describe } from 'node:test';
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
} from 'vsslib';
import { Algorithms } from 'vsslib/enums';
import { resolveTestConfig } from './environ';
import { createRawSharing, mockPublicRecoverySetup } from './helpers';
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
    for (const errorOnInvalid of [true, false]) {
      await assert.rejects(recoverPublic(ctx, [forged, ...packets.slice(1)], threshold, { errorOnInvalid }), /not in prime-order subgroup/);
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
