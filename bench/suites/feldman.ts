import {
  createFeldmanPackets,
  verifyFeldmanCommitments,
  parseFeldmanPacket,
} from 'vsslib';
import { Ctx, Params, Suite, defineCase } from '../types';
import { dealSharing, feldmanFixture, slotIndex } from '../fixtures';


/** Commitments and the packet of the shareholder determined by the slot; the cost of
 * verification grows with the threshold and, slightly, with the index */
const feldmanInput = async (ctx: Ctx, { nrShares, threshold }: Params, slot: number) => {
  const { commitments, packets } = await feldmanFixture(ctx, nrShares, threshold);
  return { commitments, packet: packets[slotIndex(slot, nrShares) - 1] };
}


const suite: Suite = {
  module: 'feldman',
  cases: [
    defineCase({
      name: 'createFeldmanPackets',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) => dealSharing(ctx, nrShares, threshold),
      run: async (_, sharing) => createFeldmanPackets(sharing),
    }),
    defineCase({
      name: 'verifyFeldmanCommitments',
      uses: ['nrShares', 'threshold'],
      setup: feldmanInput,
      run: async (ctx, { commitments, packet: { value, index } }, { threshold }) =>
        verifyFeldmanCommitments(ctx, commitments, { value, index }, threshold),
    }),
    defineCase({
      name: 'parseFeldmanPacket',
      uses: ['nrShares', 'threshold'],
      setup: feldmanInput,
      run: async (ctx, { commitments, packet }, { threshold }) =>
        parseFeldmanPacket(ctx, commitments, packet, threshold),
    }),
  ],
};

export default suite;
