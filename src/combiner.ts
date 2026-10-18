import { mod } from './arith';
import { Point, Group } from './backend';
import { InvalidPublicShare, InvalidInput } from './errors';
import { Algorithms } from './enums';
import { Algorithm, SecretShare, PublicShare, SchnorrPacket } from './types';

import { nizk } from './nizk';
import { computeLambda } from './lagrange';
import { validateIndex, validateIndexes, validateThreshold, indexToBytes } from './indexes';


export type Nonces = { [key: number]: Uint8Array };


/** Ensure that there are at least `threshold` shares */
function checkShareCount(count: number, threshold: number): void {
  validateThreshold(threshold);
  if (count < threshold) throw new InvalidInput(
    `Insufficient number of shares: ${count} < ${threshold}`
  );
}


export async function combineSecretShares<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[],
  threshold: number,
): Promise<Uint8Array> {
  checkShareCount(shares.length, threshold);
  const order = ctx.order;
  const indexes = shares.map(share => share.index);
  validateIndexes(indexes);
  let x = 0n;
  for (const { value, index } of shares) {
    const li = computeLambda(ctx, index, indexes);
    const xi = await ctx.parseScalar(value);
    x = mod(x + li * xi, order);
  }
  return ctx.scalarToBytes(x);
}


export async function combinePublicShares<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare[],
  threshold: number,
): Promise<Uint8Array> {
  checkShareCount(shares.length, threshold);
  const exp = ctx.exp;
  const indexes = shares.map(share => share.index);
  validateIndexes(indexes);
  let y = ctx.neutral;
  for (const { value, index } of shares) {
    const li = computeLambda(ctx, index, indexes);
    const yi = await ctx.parsePoint(value)
    y = await ctx.operate(y, await exp(yi, li));
  }
  return y.toBytes();
}


export async function parseSchnorrPacket<P extends Point>(
  ctx: Group<P>,
  packet: SchnorrPacket,
  { algorithm = Algorithms.DEFAULT, nonce }: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  } = {},
): Promise<PublicShare> {
  const { value, index, proof } = packet;
  validateIndex(index);
  const y = await ctx.parsePoint(value)
  const isValid = await nizk(ctx, algorithm).verifyDlog(
    {
      u: ctx.generator,
      v: y,
    },
    proof,
    nonce,
    [indexToBytes(index)],
  );
  if (!isValid)
    throw new InvalidPublicShare(`Invalid packet with index ${index}`);
  return { value, index };
}


export async function recoverPublic<P extends Point>(
  ctx: Group<P>,
  packets: SchnorrPacket[],
  threshold: number,
  {
    algorithm = Algorithms.DEFAULT,
    nonces = {},
    errorOnInvalid = true,
  }: {
    algorithm?: Algorithm,
    nonces?: Nonces,
    errorOnInvalid?: boolean,
  } = {},
): Promise<{ recovered: Uint8Array, blame: PublicShare[] }> {
  checkShareCount(packets.length, threshold);
  // Malformed or duplicate indexes cannot be attributed to a single
  // shareholder, so they are rejected regardless of errorOnInvalid
  validateIndexes(packets.map(packet => packet.index));
  const shares = [];
  const blame = [];
  for (const packet of packets) {
    const nonce = nonces[packet.index];
    try {
      shares.push(await parseSchnorrPacket(ctx, packet, { algorithm, nonce }));
    } catch (err: unknown) {
      if (!(err instanceof InvalidPublicShare) || errorOnInvalid) throw err;
      blame.push({ value: packet.value, index: packet.index });
    }
  }
  // Fewer than threshold valid shares interpolate to a wrong result
  if (shares.length < threshold) throw new InvalidPublicShare(
    `Insufficient number of valid shares: ${shares.length} < ${threshold}`
  );
  // Interpolate over valid shares only, so that blamed indexes do not
  // distort the Lagrange coefficients
  const recovered = await combinePublicShares(ctx, shares, threshold);
  return { recovered, blame };
}
