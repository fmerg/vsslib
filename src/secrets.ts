import { Group, Point } from './backend';
import { mod } from './arith';


export async function randomSecret<P extends Point>(ctx: Group<P>): Promise<{
  secret: Uint8Array, publicBytes: Uint8Array
}> {
  const secret = await ctx.generateSecret();
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const y = await ctx.exp(g, x);
  const publicBytes = y.toBytes();
  return { secret, publicBytes };
}


export async function extractPublic<P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array
): Promise<Uint8Array> {
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const y = await ctx.exp(g, x);
  return y.toBytes();
}


export async function randomPublic<P extends Point>(
  ctx: Group<P>
): Promise<Uint8Array> {
  return (await ctx.randomPoint()).toBytes();
}


export async function unpackScalar<P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array
): Promise<bigint> {
  return ctx.parseScalar(secret);
}


export async function unpackPoint<P extends Point>(
  ctx: Group<P>,
  publicBytes: Uint8Array
): Promise<P> {
  return ctx.parsePoint(publicBytes);
}


export async function isEqualSecret<P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array,
): Promise<boolean> {
  // TODO: Make this constant-time
  return ctx.leBuff2Scalar(lhs) == ctx.leBuff2Scalar(rhs);
}


export async function isEqualPublic<P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array
): Promise<boolean> {
  // TODO: Ensure that this is constant-time
  const y = await ctx.parsePoint(lhs);
  const u = await ctx.parsePoint(rhs);
  return y.equals(u);
}

export async function isKeypair<P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array,
  publicBytes: Uint8Array
): Promise<boolean> {
  // TODO: Ensure that this is constant-time
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const u = await ctx.parsePoint(publicBytes);
  const y = await ctx.exp(g, x);
  return y.equals(u);
}


export function addSecrets<P extends Point>(
  ctx: Group<P>,
  secrets: Uint8Array[]
): Uint8Array {
  if (secrets.length == 0) return ctx.scalar2Buff(0n);
  const result = secrets.map(s => ctx.leBuff2Scalar(s)).reduce(
    (acc, x) => mod(acc + x, ctx.order)
  );
  return ctx.scalar2Buff(result);
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
