import { Point, Group } from './backend';
import { InvalidSecretShare, InvalidInput } from './errors';
import { Algorithm, SecretShare, SecretPacket, SchnorrPacket } from './types';
import { Algorithms } from './enums';

import { nizk } from './nizk';
import { validateIndex, validateThreshold, indexToBytes } from './indexes';


/** Parse a Pedersen base, rejecting the neutral element and the generator,
 * whose discrete logs are known */
export async function parsePedersenBase<P extends Point>(
  ctx: Group<P>,
  pedersenBase: Uint8Array,
): Promise<P> {
  const h = await ctx.parsePoint(pedersenBase);
  if (await h.equals(ctx.neutral) || await h.equals(ctx.generator)) throw new InvalidInput(
    'Pedersen base must be neither the neutral element nor the generator'
  );
  return h;
}


/** Evaluate `Π_j C_j ^ (index ^ j)` in the exponent using Horner's rule,
 * ensuring that there is one commitment per coefficient of a `threshold`-sharing */
async function evalCommitments<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  index: number,
  threshold: number,
): Promise<P> {
  validateThreshold(threshold);
  if (commitments.length !== threshold) throw new InvalidSecretShare(
    `Invalid number of commitments: expected ${threshold}, got ${commitments.length}`
  );
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
  commitments: Uint8Array[],
  share: SecretShare,
  threshold: number,
): Promise<boolean> {
  const { value, index } = share;
  validateIndex(index);
  const x = await ctx.parseScalar(value);
  const g = ctx.generator;
  const lhs = await ctx.exp(g, x);
  const rhs = await evalCommitments(ctx, commitments, index, threshold);
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
  return true;
}


export async function verifyPedersenCommitments<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  pedersenBase: Uint8Array,
  share: SecretShare,
  binding: Uint8Array,
  threshold: number,
): Promise<boolean> {
  const { value, index } = share;
  validateIndex(index);
  const exp = ctx.exp;
  const g = ctx.generator;
  const h = await parsePedersenBase(ctx, pedersenBase);
  const x = await ctx.parseScalar(value);
  const s = await ctx.parseScalar(binding);
  const lhs = await ctx.operate(
    await exp(g, x),
    await exp(h, s)
  );
  const rhs = await evalCommitments(ctx, commitments, index, threshold);
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
  threshold: number,
): Promise<{ share: SecretShare }> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmanCommitments(ctx, commitments, share, threshold);
  return { share };
}


export async function parsePedersenPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  pedersenBase: Uint8Array,
  packet: SecretPacket,
  threshold: number,
): Promise<{ share: SecretShare, binding: Uint8Array }> {
  const { value, index, binding } = packet;
  if (!binding)
    throw new InvalidInput(
      `No binding found for index ${index}`
    );
  const share = { value, index }
  await verifyPedersenCommitments(
    ctx, commitments, pedersenBase, share, binding, threshold,
  );
  return { share, binding };
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
  validateIndex(index);
  const g = ctx.generator;
  const x = await ctx.parseScalar(value);
  const y = await ctx.exp(g, x);
  const proof = await nizk(ctx, algorithm).proveDlog(
    x, { u: g, v: y }, nonce, [indexToBytes(index)]
  );
  return { value: y.toBytes(), index, proof };
}
