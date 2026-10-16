import { bytesToHex } from '@noble/hashes/utils.js';
import { Point, Group } from '../backend';
import { randomPolynomial } from '../polynomials';
import { InvalidSecretShare, InvalidInput } from '../errors';
import { validateIndex } from '../indexes';
import { SecretShare, SecretPacket } from '../types';

import { ShamirSharing } from './shamir';
import { evalCommitments } from './commitments';


const PEDERSEN_BASE_DST = new TextEncoder().encode('vsslib:pedersen-base');


/** Number of parsed and precomputed Pedersen bases kept per group class; the
 * least recently used is evicted */
const PEDERSEN_BASE_CACHE = 8;

// By group class, so that a custom backend reusing the name of a system never
// receives points of another class, then by system and encoding. Groups are
// created anew by every initBackend call, so a cache per group would not hit
let pedersenBases = new WeakMap<object, Map<string, Point>>();

/** @internal Empty the cache of Pedersen bases, e.g. between tests */
export function clearPedersenBases(): void {
  pedersenBases = new WeakMap();
}


/** Derive from a public seed a Pedersen base whose discrete log is unknown */
export async function derivePedersenBase<P extends Point>(
  ctx: Group<P>,
  seed: Uint8Array = new Uint8Array(),
): Promise<Uint8Array> {
  return (await ctx.hashToPoint(seed, PEDERSEN_BASE_DST)).toBytes();
}


/** Parse a Pedersen base, rejecting the neutral element and the generator,
 * whose discrete logs are known. Valid bases are prepared by precomputeBase
 * and cached, so that later calls skip parsing and reuse the precomputation */
export async function parsePedersenBase<P extends Point>(
  ctx: Group<P>,
  pedersenBase: Uint8Array,
): Promise<P> {
  const key = `${ctx.system}:${bytesToHex(pedersenBase)}`;
  let bases = pedersenBases.get(ctx.constructor);
  const cached = bases?.get(key);
  if (bases && cached) {
    // Maps iterate in insertion order, which reinsertion turns into recency
    bases.delete(key);
    bases.set(key, cached);
    return cached as P;
  }
  const h = await ctx.parsePoint(pedersenBase);
  if (await h.equals(ctx.neutral) || await h.equals(ctx.generator)) throw new InvalidInput(
    'Pedersen base must be neither the neutral element nor the generator'
  );
  const base = ctx.precomputeBase(h);
  if (!bases) {
    bases = new Map();
    pedersenBases.set(ctx.constructor, bases);
  }
  bases.set(key, base);
  if (bases.size > PEDERSEN_BASE_CACHE) bases.delete(bases.keys().next().value!);
  return base;
}


/** Pedersen commitments and one packet per secret share, each with its binding;
 * takes no ctx, as the sharing carries its group */
export async function createPedersenPackets<P extends Point>(
  sharing: ShamirSharing<P>,
  pedersenBase: Uint8Array,
): Promise<{ packets: SecretPacket[], commitments: Uint8Array[] }> {
  const { ctx } = sharing;
  const { expSecret, operate, generator: g } = ctx;
  const h = await parsePedersenBase(ctx, pedersenBase);
  const { coeffs, degree } = sharing.polynomial;
  const bindingPolynomial = await randomPolynomial(ctx, degree);
  const commitments = [];
  for (const [i, a] of coeffs.entries()) {
    const b = bindingPolynomial.coeffs[i];
    commitments.push((await operate(await expSecret(g, a), await expSecret(h, b))).toBytes());
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
  const expSecret = ctx.expSecret;
  const g = ctx.generator;
  const h = await parsePedersenBase(ctx, pedersenBase);
  const x = await ctx.parseScalar(value);
  const s = await ctx.parseScalar(binding);
  const lhs = await ctx.operate(
    await expSecret(g, x),
    await expSecret(h, s)
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
