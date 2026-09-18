import {
  shareSecret,
  combineSecretShares,
  combinePublicShares,
} from 'vsslib';
import { Ctx, Params, Suite, defineCase } from '../types';
import { dealSharing, slotIndexes } from '../fixtures';


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
  module: 'shamir',
  cases: [
    // Interpolates t points; the number of shares only bounds the indexes
    defineCase({
      name: 'shareSecret',
      uses: ['threshold'],
      setup: async () => undefined,
      run: async (ctx, _, { nrShares, threshold }) => shareSecret(ctx, nrShares, threshold),
    }),
    defineCase({
      name: 'getSecretShares',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) => dealSharing(ctx, nrShares, threshold),
      run: async (_, sharing) => sharing.getSecretShares(),
    }),
    defineCase({
      name: 'getPublicShares',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) => dealSharing(ctx, nrShares, threshold),
      run: async (_, sharing) => sharing.getPublicShares(),
    }),
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
  ],
};

export default suite;
