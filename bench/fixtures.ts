import {
  shareSecret,
  derivePedersenBase,
  createFeldmanPackets,
  createPedersenPackets,
  createSchnorrPacket,
  randomNonce,
} from 'vsslib';
import type { Algorithm, SecretPacket, SchnorrPacket, Nonces } from 'vsslib';
import { Ctx } from './types';


/** Deterministic generator of integers in [min, max), seeded by the slot of
 * the input pool (mulberry32). Share indexes drive the cost of operations,
 * e.g. through the size of Lagrange coefficients, so a run-dependent choice
 * would make runs measure different input mixes */
export const slotRandom = (slot: number) => {
  let state = (slot + 1) * 0x9e3779b9 >>> 0;
  return (min: number, max: number): number => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    const uniform = ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
    return min + Math.floor(uniform * (max - min));
  };
}


/** Share index in 1..n, determined by the slot */
export const slotIndex = (slot: number, nrShares: number): number =>
  slotRandom(slot)(1, nrShares + 1);


/** Set of `size` distinct indexes in 1..n, as a qualified set of shareholders
 * would be, determined by the slot */
export const slotIndexes = (slot: number, nrShares: number, size: number): number[] => {
  const random = slotRandom(slot);
  const indexes = Array.from({ length: nrShares }, (_, i) => i + 1);
  for (let i = indexes.length - 1; i > 0; i--) {
    const j = random(0, i + 1);
    [indexes[i], indexes[j]] = [indexes[j], indexes[i]];
  }
  return indexes.slice(0, size);
}


export const dealSharing = async (ctx: Ctx, nrShares: number, threshold: number) =>
  (await shareSecret(ctx, nrShares, threshold)).sharing;


export type FeldmanFixture = {
  commitments: Uint8Array[];
  packets: SecretPacket[];
};

export const feldmanFixture = async (
  ctx: Ctx, nrShares: number, threshold: number
): Promise<FeldmanFixture> => {
  const sharing = await dealSharing(ctx, nrShares, threshold);
  return createFeldmanPackets(sharing);
}


export type PedersenFixture = FeldmanFixture & { pedersenBase: Uint8Array };

/** The Pedersen base of every input, derived from the default seed: parties
 * agree on one base and reuse it, which a per-input base would not reflect */
export const benchPedersenBase = async (ctx: Ctx): Promise<Uint8Array> =>
  derivePedersenBase(ctx);

export const pedersenFixture = async (
  ctx: Ctx, nrShares: number, threshold: number
): Promise<PedersenFixture> => {
  const pedersenBase = await benchPedersenBase(ctx);
  const sharing = await dealSharing(ctx, nrShares, threshold);
  return { pedersenBase, ...await createPedersenPackets(sharing, pedersenBase) };
}


export type SchnorrFixture = {
  packets: SchnorrPacket[];
  nonces: Nonces;
};

/** Schnorr packets of all shareholders, each proof bound to its own nonce */
export const schnorrFixture = async (
  ctx: Ctx, nrShares: number, threshold: number, algorithm: Algorithm
): Promise<SchnorrFixture> => {
  const sharing = await dealSharing(ctx, nrShares, threshold);
  const packets = [];
  const nonces: Nonces = {};
  for (const share of await sharing.getSecretShares()) {
    const nonce = randomNonce();
    nonces[share.index] = nonce;
    packets.push(await createSchnorrPacket(ctx, share, { algorithm, nonce }));
  }
  return { packets, nonces };
}
