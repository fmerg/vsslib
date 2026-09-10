import {
  combineSecretShares,
  combinePublicShares,
  parseSchnorrPacket,
  recoverPublic,
} from 'vsslib';
import { Ctx, Params, Suite, defineCase } from '../types';
import { dealSharing, schnorrFixture, slotIndex, slotIndexes } from '../fixtures';


/** Shares of a qualified set of exactly t shareholders, determined by the slot */
const qualifiedShares = async <S extends { index: number }>(
  ctx: Ctx,
  { nrShares, threshold }: Params,
  slot: number,
  extract: (sharing: Awaited<ReturnType<typeof dealSharing>>) => Promise<S[]>,
): Promise<S[]> => {
  const shares = await extract(await dealSharing(ctx, nrShares, threshold));
  return slotIndexes(slot, nrShares, threshold).map(index => shares[index - 1]);
}


const suite: Suite = {
  module: 'combiner',
  cases: [
    defineCase({
      name: 'combineSecretShares',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, params, slot) => qualifiedShares(ctx, params, slot, s => s.getSecretShares()),
      run: async (ctx, shares, { threshold }) => combineSecretShares(ctx, shares, threshold),
    }),
    defineCase({
      name: 'combinePublicShares',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, params, slot) => qualifiedShares(ctx, params, slot, s => s.getPublicShares()),
      run: async (ctx, shares, { threshold }) => combinePublicShares(ctx, shares, threshold),
    }),
    // Verification of a single packet, whose proof binds its own nonce
    defineCase({
      name: 'parseSchnorrPacket',
      uses: ['algorithm'],
      setup: async (ctx, { nrShares, threshold, algorithm }, slot) => {
        const { packets, nonces } = await schnorrFixture(ctx, nrShares, threshold, algorithm);
        const index = slotIndex(slot, nrShares);
        return { packet: packets[index - 1], nonce: nonces[index] };
      },
      run: async (ctx, { packet, nonce }, { algorithm }) =>
        parseSchnorrPacket(ctx, packet, { algorithm, nonce }),
    }),
    // Verification of all n packets and interpolation over them
    defineCase({
      name: 'recoverPublic',
      uses: ['algorithm', 'nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold, algorithm }) =>
        schnorrFixture(ctx, nrShares, threshold, algorithm),
      run: async (ctx, { packets, nonces }, { threshold, algorithm }) =>
        recoverPublic(ctx, packets, threshold, { algorithm, nonces }),
    }),
  ],
};

export default suite;
