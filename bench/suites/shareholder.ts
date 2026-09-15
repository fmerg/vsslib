import {
  randomSecret,
  randomNonce,
  verifyFeldmanCommitments,
  verifyPedersenCommitments,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
} from 'vsslib';
import { Ctx, Params, Suite, defineCase } from '../types';
import { feldmanFixture, pedersenFixture, slotIndex } from '../fixtures';


/** Commitments and the packet of the shareholder determined by the slot; the cost of
 * verification grows with the threshold and, slightly, with the index */
const feldmanInput = async (ctx: Ctx, { nrShares, threshold }: Params, slot: number) => {
  const { commitments, packets } = await feldmanFixture(ctx, nrShares, threshold);
  return { commitments, packet: packets[slotIndex(slot, nrShares) - 1] };
}


const pedersenInput = async (ctx: Ctx, { nrShares, threshold }: Params, slot: number) => {
  const { pedersenBase, commitments, packets } = await pedersenFixture(ctx, nrShares, threshold);
  return { pedersenBase, commitments, packet: packets[slotIndex(slot, nrShares) - 1] };
}


/** Random secret share of the shareholder determined by the slot */
const shareInput = async (ctx: Ctx, { nrShares }: Params, slot: number) => ({
  value: (await randomSecret(ctx)).secret,
  index: slotIndex(slot, nrShares),
});


const suite: Suite = {
  module: 'shareholder',
  cases: [
    defineCase({
      name: 'verifyFeldmanCommitments',
      uses: ['nrShares', 'threshold'],
      setup: feldmanInput,
      run: async (ctx, { commitments, packet: { value, index } }, { threshold }) =>
        verifyFeldmanCommitments(ctx, commitments, { value, index }, threshold),
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
      name: 'parseFeldmanPacket',
      uses: ['nrShares', 'threshold'],
      setup: feldmanInput,
      run: async (ctx, { commitments, packet }, { threshold }) =>
        parseFeldmanPacket(ctx, commitments, packet, threshold),
    }),
    defineCase({
      name: 'parsePedersenPacket',
      uses: ['nrShares', 'threshold'],
      setup: pedersenInput,
      run: async (ctx, { pedersenBase, commitments, packet }, { threshold }) =>
        parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold),
    }),
    defineCase({
      name: 'createSchnorrPacket',
      uses: ['algorithm'],
      setup: async (ctx, params, slot) => ({
        share: await shareInput(ctx, params, slot), nonce: randomNonce(),
      }),
      run: async (ctx, { share, nonce }, { algorithm }) =>
        createSchnorrPacket(ctx, share, { algorithm, nonce }),
    }),
  ],
};

export default suite;
