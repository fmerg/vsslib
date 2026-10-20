import {
  derivePedersenBase,
  createPedersenPackets,
  verifyPedersenCommitments,
  parsePedersenPacket,
} from 'vsslib';
import { Ctx, Params, Suite, defineCase } from '../types';
import { benchPedersenBase, dealSharing, pedersenFixture, slotIndex } from '../fixtures';


/** Commitments and the packet of the shareholder determined by the slot; the cost of
 * verification grows with the threshold and, slightly, with the index */
const pedersenInput = (newBase = false) => async (
  ctx: Ctx, { nrShares, threshold }: Params, slot: number
) => {
  const { pedersenBase, commitments, packets } = await pedersenFixture(
    ctx, nrShares, threshold, newBase
  );
  return { pedersenBase, commitments, packet: packets[slotIndex(slot, nrShares) - 1] };
}


const suite: Suite = {
  module: 'pedersen',
  cases: [
    defineCase({
      name: 'derivePedersenBase',
      uses: [],
      setup: async () => undefined,
      run: async (ctx) => derivePedersenBase(ctx),
    }),
    defineCase({
      name: 'createPedersenPackets',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) => ({
        sharing: await dealSharing(ctx, nrShares, threshold),
        pedersenBase: await benchPedersenBase(ctx),
      }),
      run: async (_, { sharing, pedersenBase }) => createPedersenPackets(sharing, pedersenBase),
    }),
    defineCase({
      name: 'verifyPedersenCommitments',
      uses: ['nrShares', 'threshold'],
      setup: pedersenInput(),
      run: async (ctx, { pedersenBase, commitments, packet }, { threshold }) => {
        const { value, index, binding } = packet;
        return verifyPedersenCommitments(
          ctx, commitments, pedersenBase, { value, index }, binding!, threshold
        );
      },
    }),
    defineCase({
      // First use of a base, as by a shareholder under a per-session base: a
      // base per slot, cycled through more bases than vsslib caches (unless
      // --pool is at most 8), so that every call parses afresh
      name: 'verifyPedersenNewBase',
      uses: ['nrShares', 'threshold'],
      setup: pedersenInput(true),
      run: async (ctx, { pedersenBase, commitments, packet }, { threshold }) => {
        const { value, index, binding } = packet;
        return verifyPedersenCommitments(
          ctx, commitments, pedersenBase, { value, index }, binding!, threshold
        );
      },
    }),
    defineCase({
      name: 'parsePedersenPacket',
      uses: ['nrShares', 'threshold'],
      setup: pedersenInput(),
      run: async (ctx, { pedersenBase, commitments, packet }, { threshold }) =>
        parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold),
    }),
  ],
};

export default suite;
