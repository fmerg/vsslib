import { bytesToHex } from '@noble/hashes/utils.js';
import { Point, Group } from '../backend';
import { randomPolynomial } from '../polynomials';
import { InvalidSecretShare, InvalidInput } from '../errors';
import { validateIndex } from '../indexes';
import { SecretShare, SecretPacket } from '../types';

import { ShamirSharing } from './shamir';
import { evalCommitments } from './commitments';


const PEDERSEN_BASE_DST = new TextEncoder().encode('vsslib:pedersen-base');


/** Number of parsed Pedersen bases kept per group class; the least recently
 * used is evicted */
const PEDERSEN_BASE_CACHE = 8;

/** A base is prepared by precomputeBase on its second use, so that a base used
 * once costs no more than without the cache */
type _CachedBase = { point: Point, precomputed: boolean };

// By group class, so that a custom backend reusing the name of a system never
// receives points of another class, then by group parameters and encoding.
// Groups are created anew by every initBackend call, so a cache per group
// would not hit
let pedersenBases = new WeakMap<object, Map<string, _CachedBase>>();

// Cache key prefix per group, which spares encoding the generator on every call
const groupKeys = new WeakMap<object, string>();

const groupKey = <P extends Point>(ctx: Group<P>): string => {
  let key = groupKeys.get(ctx);
  if (key === undefined) {
    key = `${ctx.system}:${ctx.order}:${bytesToHex(ctx.generator.toBytes())}`;
    groupKeys.set(ctx, key);
  }
  return key;
}

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


async function validatePedersenBase<P extends Point>(
  ctx: Group<P>,
  pedersenBase: Uint8Array,
): Promise<P> {
  const h = await ctx.parsePoint(pedersenBase);
  if (await h.equals(ctx.neutral) || await h.equals(ctx.generator)) throw new InvalidInput(
    'Pedersen base must be neither the neutral element nor the generator'
  );
  return h;
}


/** Parse a Pedersen base, rejecting the neutral element and the generator,
 * whose discrete logs are known. Valid bases are cached, so that later calls
 * skip parsing, and prepared by precomputeBase on their second use */
export async function parsePedersenBase<P extends Point>(
  ctx: Group<P>,
  pedersenBase: Uint8Array,
): Promise<P> {
  // Anything else is rejected by parsing, as InvalidInput
  if (!(pedersenBase instanceof Uint8Array)) return validatePedersenBase(ctx, pedersenBase);
  const key = `${groupKey(ctx)}:${bytesToHex(pedersenBase)}`;
  let entry = pedersenBases.get(ctx.constructor)?.get(key);
  if (entry && !entry.precomputed) {
    entry.point = ctx.precomputeBase(entry.point as P);
    entry.precomputed = true;
  }
  if (!entry) {
    const h = await validatePedersenBase(ctx, pedersenBase);
    // Concurrent calls may have cached the base meanwhile; keep the first
    entry = pedersenBases.get(ctx.constructor)?.get(key) ?? { point: h, precomputed: false };
  }
  let bases = pedersenBases.get(ctx.constructor);
  if (!bases) {
    bases = new Map();
    pedersenBases.set(ctx.constructor, bases);
  }
  // Maps iterate in insertion order, which reinsertion turns into recency
  bases.delete(key);
  bases.set(key, entry);
  if (bases.size > PEDERSEN_BASE_CACHE) bases.delete(bases.keys().next().value!);
  return entry.point as P;
}


/** Pedersen commitments and one packet per secret share, each with its binding;
 * takes no ctx, as the sharing carries its group. Commitments always number
 * `threshold`: vanished top coefficients, of the sharing or of the binding
 * polynomial, count as zero */
export async function createPedersenPackets<P extends Point>(
  sharing: ShamirSharing<P>,
  pedersenBase: Uint8Array,
): Promise<{
  /** One per share, with its binding, to be sent privately to its shareholder */
  packets: SecretPacket[],
  /** `g^a_i * h^b_i` for the coefficients `a_i` of the sharing polynomial and
   * `b_i` of a random binding polynomial, to be broadcast */
  commitments: Uint8Array[],
}> {
  const { ctx } = sharing;
  const { expSecret, operate, generator: g } = ctx;
  const h = await parsePedersenBase(ctx, pedersenBase);
  const { threshold, polynomial: { coeffs } } = sharing;
  const bindingPolynomial = await randomPolynomial(ctx, threshold - 1);
  const commitments = [];
  for (let i = 0; i < threshold; i++) {
    const a = coeffs[i] ?? 0n;
    const b = bindingPolynomial.coeffs[i] ?? 0n;
    commitments.push((await operate(await expSecret(g, a), await expSecret(h, b))).toBytes());
  }
  const shares = await sharing.getSecretShares();
  const packets = shares.map((share) => ({
    ...share,
    binding: ctx.scalarToBytes(bindingPolynomial.evaluate(share.index)),
  }));
  return { packets, commitments };
}


/** Verify a secret share and its binding against Pedersen commitments of a
 * `threshold`-sharing under `pedersenBase`; returns true or throws
 * InvalidSecretShare if they do not match or the commitments do not number
 * `threshold`, and InvalidInput on malformed input or an invalid base */
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


/** Extract the secret share and binding of a Pedersen packet, verified as by
 * {@link verifyPedersenCommitments}, which throws on failure; throws
 * InvalidInput if the packet has no binding */
export async function parsePedersenPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  pedersenBase: Uint8Array,
  packet: SecretPacket,
  threshold: number,
): Promise<{
  /** The verified share */
  share: SecretShare,
  /** Its binding, needed only for verification */
  binding: Uint8Array,
}> {
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
