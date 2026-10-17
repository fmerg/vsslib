import { Point, Group } from './backend';
import { InvalidSecretShare, InvalidInput } from './errors';
import { extractPublic } from './secrets';
import { Algorithm, SecretShare, PublicShare, SecretPacket, SchnorrPacket } from './types';
import { Algorithms } from './enums';

import { nizk } from './nizk';


/** Evaluate `Π_j C_j ^ (index ^ j)` in the exponent using Horner's rule */
async function evalCommitments<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  index: number,
): Promise<P> {
  const x = BigInt(index);
  let acc = ctx.neutral;
  for (let j = commitments.length - 1; j >= 0; j--) {
    const c = await ctx.parsePoint(commitments[j]);
    acc = await ctx.operate(await ctx.exp(acc, x), c);
  }
  return acc;
}


export async function verifyFeldmanCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  commitments: Uint8Array[],
): Promise<boolean> {
  const { value, index } = share;
  const x = await ctx.parseScalar(value);
  const g = ctx.generator;
  const lhs = await ctx.exp(g, x);
  const rhs = await evalCommitments(ctx, commitments, index);
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
  return true;
}


export async function verifyPedersenCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  binding: Uint8Array,
  publicBytes: Uint8Array,
  commitments: Uint8Array[],
): Promise<boolean> {
  const { value, index } = share;
  const exp = ctx.exp;
  const g = ctx.generator;
  const h = await ctx.parsePoint(publicBytes);
  const x = await ctx.parseScalar(value);
  const s = await ctx.parseScalar(binding);
  const lhs = await ctx.operate(
    await exp(g, x),
    await exp(h, s)
  );
  const rhs = await evalCommitments(ctx, commitments, index);
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
  return true;
}


export async function parseFeldmanPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SecretPacket,
): Promise<{ share: SecretShare }> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmanCommitments(ctx, share, commitments);
  return { share };
}


export async function parsePedersenPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  publicBytes: Uint8Array,
  packet: SecretPacket,
): Promise<{ share: SecretShare, binding: Uint8Array }> {
  const { value, index, binding } = packet;
  if (!binding)
    throw new InvalidInput(
      `No binding found for index ${index}`
    );
  const share = { value, index }
  await verifyPedersenCommitments(
    ctx, share, binding, publicBytes, commitments,
  );
  return { share, binding };
}

export async function extractPublicShare<P extends Point>(
  ctx: Group<P>, share: SecretShare
): Promise<PublicShare> {
  const { value: secret, index } = share;
  return { value: await extractPublic(ctx, secret), index };
}


export async function createSchnorrPacket<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  { algorithm = Algorithms.DEFAULT, nonce }: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  } = {},
): Promise<SchnorrPacket> {
  const { value, index } = share;
  const g = ctx.generator;
  const x = await ctx.parseScalar(value);
  const y = await ctx.exp(g, x);
  const proof = await nizk(ctx, algorithm).proveDlog(x, { u: g, v: y }, nonce);
  return { value: y.toBytes(), index, proof };
}
