import {
  shareSecret,
  createFeldmanPackets,
  createPedersenPackets,
  derivePedersenBase,
  randomNonce,
} from 'vsslib';
import { Suite, defineCase } from '../types';
import { dealSharing } from '../fixtures';


const suite: Suite = {
  module: 'dealer',
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
      name: 'createFeldmanPackets',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) => dealSharing(ctx, nrShares, threshold),
      run: async (_, sharing) => createFeldmanPackets(sharing),
    }),
    defineCase({
      name: 'createPedersenPackets',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) => ({
        sharing: await dealSharing(ctx, nrShares, threshold),
        pedersenBase: await derivePedersenBase(ctx, randomNonce()),
      }),
      run: async (_, { sharing, pedersenBase }) => createPedersenPackets(sharing, pedersenBase),
    }),
  ],
};

export default suite;
