import { Group, Point } from '../backend';
import { mod } from '../arith';
import { isEqualBytes } from '../bytes';


/** Random secret with its public counterpart */
export async function randomSecret<P extends Point>(ctx: Group<P>): Promise<{
  /** Encoded uniform scalar */
  secret: Uint8Array,
  /** Encoded generator raised to the secret */
  publicBytes: Uint8Array,
}> {
  const secret = await ctx.generateSecret();
  const publicBytes = await extractPublic(ctx, secret);
  return { secret, publicBytes };
}


/** Public counterpart of a secret, i.e. the generator raised to it; throws
 * InvalidInput on an invalid secret */
export async function extractPublic<P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array
): Promise<Uint8Array> {
  const g = ctx.generator;
  const x = await ctx.parseScalar(secret);
  const y = await ctx.expSecret(g, x);
  return y.toBytes();
}


/** Random group element, whose discrete log is discarded */
export async function randomPublic<P extends Point>(
  ctx: Group<P>
): Promise<Uint8Array> {
  return (await ctx.randomPoint()).toBytes();
}


/** Decode a scalar; throws InvalidInput unless the bytes are a canonical
 * encoding of a nonzero scalar below the group order */
export async function parseScalar<P extends Point>(
  ctx: Group<P>,
  bytes: Uint8Array
): Promise<bigint> {
  return ctx.parseScalar(bytes);
}


/** Decode a group element; throws InvalidInput unless the bytes are a
 * canonical encoding of an element of the prime-order subgroup */
export async function parsePoint<P extends Point>(
  ctx: Group<P>,
  bytes: Uint8Array
): Promise<P> {
  return ctx.parsePoint(bytes);
}


/** Whether two secrets are equal, compared in constant time; throws
 * InvalidInput on an invalid secret */
export async function isEqualSecret<P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array,
): Promise<boolean> {
  // SECURITY!
  // Parsing rejects non-canonical encodings, so that equal secrets have
  // equal bytes, which are compared in constant time
  await ctx.parseScalar(lhs);
  await ctx.parseScalar(rhs);
  return isEqualBytes(lhs, rhs);
}


/** Whether two group elements are equal, compared in constant time; throws
 * InvalidInput on an invalid element */
export async function isEqualPublic<P extends Point>(
  ctx: Group<P>,
  lhs: Uint8Array,
  rhs: Uint8Array
): Promise<boolean> {
  // SECURITY!
  // Parsing rejects non-canonical encodings, so that equal points have
  // equal bytes, which are compared in constant time
  await ctx.parsePoint(lhs);
  await ctx.parsePoint(rhs);
  return isEqualBytes(lhs, rhs);
}

/** Whether `publicBytes` is the public counterpart of `secret`, compared in
 * constant time; throws InvalidInput on invalid input */
export async function isKeypair<P extends Point>(
  ctx: Group<P>,
  secret: Uint8Array,
  publicBytes: Uint8Array
): Promise<boolean> {
  const g = ctx.generator;
  const x = await ctx.parseScalar(secret);
  await ctx.parsePoint(publicBytes);
  const y = await ctx.expSecret(g, x);
  // SECURITY! constant-time comparison of the encodings
  return isEqualBytes(y.toBytes(), publicBytes);
}


/** Sum of secrets modulo the group order, e.g. the joint secret of a DKG;
 * throws InvalidInput on an invalid secret */
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


/** Product of group elements, the public counterpart of the sum of their
 * secrets, e.g. the joint public key of a DKG; the neutral element for none.
 * Throws InvalidInput on an invalid element */
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
