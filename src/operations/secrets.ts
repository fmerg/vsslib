import { Group, Point } from '../backend';
import { mod } from '../arith';
import { isEqualBytes } from '../bytes';


export async function randomSecret<P extends Point>(ctx: Group<P>): Promise<{
  secret: Uint8Array, publicBytes: Uint8Array
}> {
  const secret = await ctx.generateSecret();
  const publicBytes = await extractPublic(ctx, secret);
  return { secret, publicBytes };
}


export async function extractPublic<P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array
): Promise<Uint8Array> {
  const g = ctx.generator;
  const x = await ctx.parseScalar(secret);
  const y = await ctx.expSecret(g, x);
  return y.toBytes();
}


export async function randomPublic<P extends Point>(
  ctx: Group<P>
): Promise<Uint8Array> {
  return (await ctx.randomPoint()).toBytes();
}


export async function parseScalar<P extends Point>(
  ctx: Group<P>,
  bytes: Uint8Array
): Promise<bigint> {
  return ctx.parseScalar(bytes);
}


export async function parsePoint<P extends Point>(
  ctx: Group<P>,
  bytes: Uint8Array
): Promise<P> {
  return ctx.parsePoint(bytes);
}


export async function isEqualSecret<P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array,
): Promise<boolean> {
  // Parsing rejects non-canonical encodings, so that equal secrets have
  // equal bytes, which are compared in constant time
  await ctx.parseScalar(lhs);
  await ctx.parseScalar(rhs);
  return isEqualBytes(lhs, rhs);
}


export async function isEqualPublic<P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array
): Promise<boolean> {
  // Parsing rejects non-canonical encodings, so that equal points have
  // equal bytes, which are compared in constant time
  await ctx.parsePoint(lhs);
  await ctx.parsePoint(rhs);
  return isEqualBytes(lhs, rhs);
}

export async function isKeypair<P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array,
  publicBytes: Uint8Array
): Promise<boolean> {
  const g = ctx.generator;
  const x = await ctx.parseScalar(secret);
  await ctx.parsePoint(publicBytes);
  const y = await ctx.expSecret(g, x);
  return isEqualBytes(y.toBytes(), publicBytes);
}


export async function addSecrets<P extends Point>(
  ctx: Group<P>,
  secrets: Uint8Array[]
): Promise<Uint8Array> {
  let acc = 0n;
  for (const secret of secrets) {
    acc = mod(acc + await ctx.parseScalar(secret), ctx.order);
  }
  return ctx.scalarToBytes(acc);
}


export async function combinePublics<P extends Point>(
  ctx: Group<P>,
  publics: Uint8Array[]
): Promise<Uint8Array> {
  let acc = ctx.neutral;
  for (const y of publics.map(async p => ctx.parsePoint(p))) {
    acc = await ctx.operate(acc, await y);
  }
  return acc.toBytes();
}
