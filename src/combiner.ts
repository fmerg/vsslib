import { mod } from './arith';
import { Point, Group } from './backend';
import { InvalidPublicShare, InvalidInput } from './errors';
import { Algorithms } from './enums';
import { Algorithm, SecretShare, PublicShare, SchnorrPacket } from './types';

import { nizk } from './nizk';
import { computeLambda } from './lagrange';


export type Nonces = { [key: number]: Uint8Array };


export async function combineSecretShares<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[],
  threshold?: number
): Promise<Uint8Array> {
  if (threshold && shares.length < threshold)
    throw new InvalidInput('Insufficient number of shares');
  const order = ctx.order;
  const indexes = shares.map(share => share.index);
  let x = 0n;
  for (const { value, index } of shares) {
    const li = computeLambda(ctx, index, indexes);
    const xi = await ctx.parseScalar(value);
    x = mod(x + li * xi, order);
  }
  return ctx.scalar2Buff(x);
}


export async function combinePublicShares<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare[],
  threshold?: number
): Promise<Uint8Array> {
  if (threshold && shares.length < threshold)
    throw new InvalidInput('Insufficient number of shares');
  const exp = ctx.exp;
  const indexes = shares.map(share => share.index);
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
  const y = await ctx.parsePoint(value)
  const isValid = await nizk(ctx, algorithm).verifyDlog(
    {
      u: ctx.generator,
      v: y,
    },
    proof,
    nonce,
  );
  if (!isValid)
    throw new InvalidPublicShare(`Invalid packet with index ${index}`);
  return { value, index };
}


export async function recoverPublic<P extends Point>(
  ctx: Group<P>,
  packets: SchnorrPacket[],
  {
    algorithm = Algorithms.DEFAULT,
    nonces = {},
    threshold,
    errorOnInvalid = true,
  }: {
    algorithm?: Algorithm,
    nonces?: Nonces,
    threshold?: number,
    errorOnInvalid?: boolean,
  } = {},
): Promise<{ recovered: Uint8Array, blame: PublicShare[] }> {
  if (threshold && packets.length < threshold) throw new InvalidInput(
    'Insufficient number of shares'
  );
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
  // Interpolate over valid shares only, so that blamed indexes do not
  // distort the Lagrange coefficients
  const recovered = await combinePublicShares(ctx, shares);
  return { recovered, blame };
}
