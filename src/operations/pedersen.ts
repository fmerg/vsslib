import { Point, Group } from '../backend';
import { randomPolynomial } from '../polynomials';
import { InvalidSecretShare, InvalidInput } from '../errors';
import { validateIndex } from '../indexes';
import { SecretShare, SecretPacket } from '../types';

import { ShamirSharing } from './shamir';
import { evalCommitments } from './commitments';


const PEDERSEN_BASE_DST = new TextEncoder().encode('vsslib:pedersen-base');


/** Derive from a public seed a Pedersen base whose discrete log is unknown */
export async function derivePedersenBase<P extends Point>(
  ctx: Group<P>,
  seed: Uint8Array = new Uint8Array(),
): Promise<Uint8Array> {
  return (await ctx.hashToPoint(seed, PEDERSEN_BASE_DST)).toBytes();
}


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


export async function createPedersenPackets<P extends Point>(
  sharing: ShamirSharing<P>,
  pedersenBase: Uint8Array,
): Promise<{ packets: SecretPacket[], commitments: Uint8Array[] }> {
  const { ctx } = sharing;
  const { exp, operate, generator: g } = ctx;
  const h = await parsePedersenBase(ctx, pedersenBase);
  const { coeffs, degree } = sharing.polynomial;
  const bindingPolynomial = await randomPolynomial(ctx, degree);
  const commitments = [];
  for (const [i, a] of coeffs.entries()) {
    const b = bindingPolynomial.coeffs[i];
    commitments.push((await operate(await exp(g, a), await exp(h, b))).toBytes());
  }
  const shares = await sharing.getSecretShares();
  const packets = shares.map((share) => ({
    ...share,
    binding: ctx.scalarToBytes(bindingPolynomial.evaluate(share.index)),
  }));
  return { packets, commitments };
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
