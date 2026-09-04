import { EcGroup } from 'vsslib/backend/elliptic';
import { nizk } from 'vsslib/nizk';
import { indexToBytes } from 'vsslib/indexes';
import {
  parsePoint,
  parseSchnorrPacket,
  recoverPublic,
  derivePedersenBase,
  InvalidInput,
} from 'vsslib';
import { Algorithms } from 'vsslib/enums';
import { resolveTestConfig } from './environ';
import { createRawSharing, mockPublicRecoverySetup } from './helpers';

const { systems, nrShares, threshold } = resolveTestConfig();


/** The point (0, -1), which has order 2 on all supported curves */
const orderTwoPoint = (ctx: EcGroup) => {
  const Point = ctx.Point;
  return Point.fromAffine({ x: 0n, y: Point.Fp.ORDER - 1n });
}


describe('Prime-order subgroup validation', () => {
  it.each(systems)('small-order points are rejected over %s', async (system) => {
    const { ctx } = await createRawSharing(system, nrShares, threshold);
    const t = orderTwoPoint(ctx);
    const mixed = ctx.generator.wrapped.add(t);
    for (const p of [t, mixed]) {
      await expect(parsePoint(ctx, p.toBytes())).rejects.toThrow('not in prime-order subgroup');
    }
  });
  it.each(systems)('public share with small-order component is rejected over %s', async (system) => {
    // The shareholder publishes y + T and retries the proof until the challenge
    // is even, so that T vanishes from the verification equation
    const { ctx, secretShares: shares } = await createRawSharing(system, nrShares, threshold);
    const { packets } = await mockPublicRecoverySetup({ ctx, shares });
    const { value, index } = shares[0];
    const x = await ctx.parseScalar(value);
    const g = ctx.generator;
    const y = await ctx.exp(g, x);
    // bytesToPoint decodes without validation
    const v = ctx.bytesToPoint(y.wrapped.add(orderTwoPoint(ctx)).toBytes());
    const protocol = nizk(ctx, Algorithms.DEFAULT);
    const extras = [indexToBytes(index)];
    let proof;
    do {
      proof = await protocol.proveDlog(x, { u: g, v }, undefined, extras);
    } while (!(await protocol.verifyDlog({ u: g, v }, proof, undefined, extras)));
    const forged = { value: v.toBytes(), index, proof };
    await expect(parseSchnorrPacket(ctx, forged)).rejects.toThrow(InvalidInput);
    for (const errorOnInvalid of [true, false]) {
      await expect(
        recoverPublic(ctx, [forged, ...packets.slice(1)], threshold, { errorOnInvalid })
      ).rejects.toThrow('not in prime-order subgroup');
    }
  });
  it.each(systems)('trivial Pedersen bases are rejected over %s', async (system) => {
    const { ctx, sharing } = await createRawSharing(system, nrShares, threshold);
    for (const base of [ctx.neutral, ctx.generator]) {
      await expect(
        sharing.createPedersenPackets(base.toBytes())
      ).rejects.toThrow('Pedersen base must be');
    }
    await expect(
      sharing.createPedersenPackets(await derivePedersenBase(ctx))
    ).resolves.toBeDefined();
  });
});
