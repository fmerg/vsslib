import { Group, Point } from './backend';

export async function generateSecret<P extends Point>(ctx: Group<P>): Promise<{
  secret: Uint8Array, publicBytes: Uint8Array
}> {
  const secret = await ctx.randomSecret();
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const y = await ctx.exp(g, x);
  const publicBytes = y.toBytes();
  return { secret, publicBytes };
}

export async function validateSecret<P extends Point>(
  ctx: Group<P>, secret: Uint8Array
): Promise<boolean> {
  return ctx.validateScalar(ctx.leBuff2Scalar(secret));

}

export async function extractPublic<P extends Point>(
  ctx: Group<P>, secret: Uint8Array
): Promise<Uint8Array> {
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const y = await ctx.exp(g, x);
  return y.toBytes();
}

export async function isEqualSecret<P extends Point>(
  ctx: Group<P>, lhs: Uint8Array, rhs: Uint8Array
): Promise<boolean> {
  // TODO: Make this constant-time
  return ctx.leBuff2Scalar(lhs) == ctx.leBuff2Scalar(rhs);
}


// TODO: Ensure that this is constant-time, or apply ctEqualBuffer instead
export async function isEqualPublic<P extends Point>(
  ctx: Group<P>, lhs: Uint8Array, rhs: Uint8Array
): Promise<boolean> {
  const y = await ctx.unpackValid(lhs);
  const u = await ctx.unpackValid(rhs);
  return y.equals(u);
}

// TODO: Ensure that this is constant-time, or apply ctEqualBuffer instead
export async function isKeypair<P extends Point>(
  ctx: Group<P>, secret: Uint8Array, publicBytes: Uint8Array
): Promise<boolean> {
  const g = ctx.generator;
  const x = ctx.leBuff2Scalar(secret);
  const u = await ctx.unpackValid(publicBytes);
  const y = await ctx.exp(g, x);
  return y.equals(u);
}
