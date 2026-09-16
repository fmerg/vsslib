import {
  randomNonce,
  derivePedersenBase,
  createPedersenPackets,
  verifyPedersenCommitments,
  parsePedersenPacket,
} from 'vsslib';
import { Ctx, Params, Suite, defineCase } from '../types';
import { dealSharing, pedersenFixture, slotIndex } from '../fixtures';


/** Commitments and the packet of the shareholder determined by the slot; the cost of
 * verification grows with the threshold and, slightly, with the index */
const pedersenInput = async (ctx: Ctx, { nrShares, threshold }: Params, slot: number) => {
  const { pedersenBase, commitments, packets } = await pedersenFixture(ctx, nrShares, threshold);
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
        pedersenBase: await derivePedersenBase(ctx, randomNonce()),
      }),
      run: async (_, { sharing, pedersenBase }) => createPedersenPackets(sharing, pedersenBase),
    }),
    defineCase({
      name: 'verifyPedersenCommitments',
      uses: ['nrShares', 'threshold'],
      setup: pedersenInput,
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
      setup: pedersenInput,
      run: async (ctx, { pedersenBase, commitments, packet }, { threshold }) =>
        parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold),
    }),
  ],
};

export default suite;
