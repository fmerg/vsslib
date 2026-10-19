import { Point, Group } from '../backend';
import { InvalidPublicShare } from '../errors';
import { Algorithms } from '../enums';
import { Algorithm, SecretShare, PublicShare, SchnorrPacket } from '../types';
import { nizk } from '../nizk';
import { validateIndex, validateIndexes, validateShareCount, indexToBytes } from '../indexes';

import { combinePublicShares } from './shamir';


export type Nonces = { [key: number]: Uint8Array };


export async function createSchnorrPacket<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  { algorithm = Algorithms.DEFAULT, nonce }: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  } = {},
): Promise<SchnorrPacket> {
  const { value, index } = share;
  validateIndex(index);
  const g = ctx.generator;
  const x = await ctx.parseScalar(value);
  const y = await ctx.exp(g, x);
  const proof = await nizk(ctx, algorithm).proveDlog(
    x, { u: g, v: y }, nonce, [indexToBytes(index)]
  );
  return { value: y.toBytes(), index, proof };
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
  validateShareCount(packets.length, threshold);
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
