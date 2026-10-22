import { Point, Group } from '../backend';
import { InvalidInput, InvalidPublicShare } from '../errors';
import { Algorithms } from '../enums';
import { Algorithm, SecretShare, PublicShare, SchnorrPacket } from '../types';
import { nizk } from '../nizk';
import { validateIndex, validateIndexes, validateShareCount, indexToBytes } from '../indexes';
import { computeLambdas } from '../lagrange';


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
  const y = await ctx.expSecret(g, x);
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
  await verifySchnorrPacket(ctx, packet, algorithm, nonce);
  return { value: packet.value, index: packet.index };
}


/** Body of parseSchnorrPacket, returning the parsed public share, so that
 * recoverPublic need not parse it again */
async function verifySchnorrPacket<P extends Point>(
  ctx: Group<P>,
  packet: SchnorrPacket,
  algorithm: Algorithm,
  nonce?: Uint8Array,
): Promise<P> {
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
  return y;
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
  const points = [];
  const indexes = [];
  const blame = [];
  for (const packet of packets) {
    const nonce = nonces[packet.index];
    try {
      points.push(await verifySchnorrPacket(ctx, packet, algorithm, nonce));
      indexes.push(packet.index);
    } catch (err: unknown) {
      // Indexes are valid at this point, so InvalidInput means a malformed
      // public share or proof, attributable to the shareholder
      const isInvalid = err instanceof InvalidPublicShare || err instanceof InvalidInput;
      if (!isInvalid || errorOnInvalid) throw err;
      blame.push({ value: packet.value, index: packet.index });
    }
  }
  // Fewer than threshold valid shares interpolate to a wrong result
  if (points.length < threshold) throw new InvalidPublicShare(
    `Insufficient number of valid shares: ${points.length} < ${threshold}`
  );
  // Interpolate over valid shares only, so that blamed indexes do not
  // distort the Lagrange coefficients. Shares and coefficients are public,
  // so variable time is safe
  const lambdas = computeLambdas(ctx, indexes);
  const recovered = (await ctx.multiExpPublic(points, lambdas)).toBytes();
  return { recovered, blame };
}
