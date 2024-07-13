import { Group, Point } from 'vsslib/backend';
import { mod, leInt2Buff } from 'vsslib/arith';
import { BadScalarError, BadPointError, InvalidInput } from 'vsslib/errors';


export const randomSecret = async <P extends Point>(ctx: Group<P>): Promise<{
  secret: Uint8Array, publicBytes: Uint8Array
}> => {
  const secret = await ctx.generateSecret();
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const y = await ctx.exp(g, x);
  const publicBytes = y.toBytes();
  return { secret, publicBytes };
}


export const extractPublic = async <P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array
): Promise<Uint8Array> => {
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const y = await ctx.exp(g, x);
  return y.toBytes();
}


export const randomPublic = async <P extends Point>(
  ctx: Group<P>
): Promise<Uint8Array> => {
  return (await ctx.randomPoint()).toBytes();
}


export const unpackScalar = async <P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array
): Promise<bigint> => {
  const scalar = ctx.leBuff2Scalar(secret);
  try {
    await ctx.validateScalar(scalar);
  } catch (err: any) {
    if (err instanceof BadScalarError) throw new InvalidInput(
      'Invalid scalar provided: ' + err.message
    )
  }
  return scalar;
}


export const unpackPoint = async <P extends Point>(
  ctx: Group<P>,
  publicBytes: Uint8Array
): Promise<P> => {
  const point = ctx.buff2Point(publicBytes);
  try {
    await ctx.validatePoint(point);
  } catch (err: any) {
    if (err instanceof BadPointError) throw new InvalidInput(
      'Invalid point provided: ' + err.message
    )
  }
  return point;
}


export const isEqualSecret = async <P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array,
): Promise<boolean> => {
  // TODO: Make this constant-time
  return ctx.leBuff2Scalar(lhs) == ctx.leBuff2Scalar(rhs);
}


export const isEqualPublic = async <P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array
): Promise<boolean> => {
  // TODO: Ensure that this is constant-time, or apply ctEqualBuffer instead
  const y = await unpackPoint(ctx, lhs);
  const u = await unpackPoint(ctx, rhs);
  return y.equals(u);
}

export const isKeypair = async <P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array,
  publicBytes: Uint8Array
): Promise<boolean> => {
  // TODO: Ensure that this is constant-time, or apply ctEqualBuffer instead
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const u = await unpackPoint(ctx, publicBytes);
  const y = await ctx.exp(g, x);
  return y.equals(u);
}


export const addSecrets = <P extends Point>(
  ctx: Group<P>,
  secrets: Uint8Array[]
): Uint8Array => {
  if (secrets.length == 0) return leInt2Buff(BigInt(0));
  const result = secrets.map(s => ctx.leBuff2Scalar(s)).reduce(
    (acc, x) => mod(acc + x, ctx.order)
  );
  return leInt2Buff(result);
}


export const combinePublics = async <P extends Point>(
  ctx: Group<P>,
  publics: Uint8Array[]
): Promise<Uint8Array> => {
  let acc = ctx.neutral;
  for (const y of publics.map(async p => unpackPoint(ctx, p))) {
    acc = await ctx.operate(acc, await y);
  }
  return acc.toBytes();
}
