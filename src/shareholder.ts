import { Point, Group } from 'vsslib/backend';
import { mod, modInv } from 'vsslib/arith';
import { InvalidSecretShare, InvalidPublicShare, InvalidInput } from 'vsslib/errors';
import { leInt2Buff } from 'vsslib/arith';
import { SecretShare, PublicShare, SecretPacket } from 'vsslib/dealer';
import { extractPublic } from 'vsslib/secrets';
import { NizkProof } from 'vsslib/nizk';
import { Algorithm } from 'vsslib/types';
import { Algorithms } from 'vsslib/enums';

import nizk from 'vsslib/nizk';

export type SchnorrPacket = PublicShare & { proof: NizkProof };


export async function verifyFeldmanCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  commitments: Uint8Array[],
): Promise<boolean> {
  const { value, index } = share;
  const x = ctx.leBuff2Scalar(share.value);
  const g = ctx.generator;
  const order = ctx.order;
  const lhs = await ctx.exp(g, x);
  let rhs = ctx.neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    const curr = await ctx.exp(c, mod(BigInt(index ** j), order));
    rhs = await ctx.operate(rhs, curr);
  }
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
  const order = ctx.order;
  const g = ctx.generator;
  const h = await ctx.unpackValid(publicBytes);
  const x = ctx.leBuff2Scalar(value);
  const s = ctx.leBuff2Scalar(binding);
  const lhs = await ctx.operate(
    await exp(g, x),
    await exp(h, s)
  );
  let rhs = ctx.neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    const curr = await exp(c, mod(BigInt(index ** j), order));
    rhs = await ctx.operate(rhs, curr);
  }
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
): Promise<SecretShare> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmanCommitments(ctx, share, commitments);
  return share;
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
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<SchnorrPacket> {
  const { value, index } = share;
  const g = ctx.generator;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const x = ctx.leBuff2Scalar(value);
  const y = await ctx.exp(g, x);
  const proof = await nizk(ctx, algorithm).proveDlog(x, { u: g, v: y }, nonce);
  return { value: y.toBytes(), index, proof };
}
