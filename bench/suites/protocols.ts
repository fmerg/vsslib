/** End-to-end protocol flows of the examples: the computation of all parties,
 * run in turn in one process, i.e. the total work of a run without any
 * networking */
import { derivePedersenBase, randomNonce, shareSecret } from 'vsslib';
import { runSss } from '../../examples/sss';
import { distributeShares, recoverPublicKey } from '../../examples/vss';
import { runDkg } from '../../examples/dkg';
import { Suite, defineCase } from '../types';
import { slotIndexes } from '../fixtures';


const suite: Suite = {
  module: 'protocols',
  cases: [
    // Dealing and reconstruction of the secret and its public counterpart by
    // a qualified set
    defineCase({
      name: 'sss',
      uses: ['nrShares', 'threshold'],
      setup: async (_, { nrShares, threshold }, slot) => slotIndexes(slot, nrShares, threshold),
      run: async (ctx, qualified, { nrShares, threshold }) =>
        runSss(ctx, nrShares, threshold, qualified),
    }),
    // Dealing with commitments and verification by every shareholder
    defineCase({
      name: 'feldmanVss',
      uses: ['nrShares', 'threshold'],
      setup: async () => undefined,
      run: async (ctx, _, { nrShares, threshold }) =>
        distributeShares(ctx, nrShares, threshold),
    }),
    defineCase({
      name: 'pedersenVss',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx) => derivePedersenBase(ctx, randomNonce()),
      run: async (ctx, pedersenBase, { nrShares, threshold }) =>
        distributeShares(ctx, nrShares, threshold, pedersenBase),
    }),
    // Every shareholder proves knowledge of its share, bound to a nonce of
    // the combiner, and the combiner verifies all proofs and interpolates
    defineCase({
      name: 'publicRecovery',
      uses: ['algorithm', 'nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) =>
        (await shareSecret(ctx, nrShares, threshold)).sharing.getSecretShares(),
      run: async (ctx, shares, { threshold, algorithm }) =>
        recoverPublicKey(ctx, shares, threshold, algorithm),
    }),
    // Pedersen DKG: n Pedersen VSS, local summation, and recovery of the
    // joint public key by every party from proofs under its own nonces
    defineCase({
      name: 'dkg',
      uses: ['algorithm', 'nrShares', 'threshold'],
      setup: async (ctx) => derivePedersenBase(ctx, randomNonce()),
      run: async (ctx, pedersenBase, { nrShares, threshold, algorithm }) =>
        runDkg(ctx, nrShares, threshold, pedersenBase, algorithm),
    }),
  ],
};

export default suite;
