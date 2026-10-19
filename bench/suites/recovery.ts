import {
  randomSecret,
  randomNonce,
  createSchnorrPacket,
  parseSchnorrPacket,
  recoverPublic,
} from 'vsslib';
import { Ctx, Params, Suite, defineCase } from '../types';
import { schnorrFixture, slotIndex } from '../fixtures';


/** Random secret share of the shareholder determined by the slot */
const shareInput = async (ctx: Ctx, { nrShares }: Params, slot: number) => ({
  value: (await randomSecret(ctx)).secret,
  index: slotIndex(slot, nrShares),
});


const suite: Suite = {
  module: 'recovery',
  cases: [
    defineCase({
      name: 'createSchnorrPacket',
      uses: ['algorithm'],
      setup: async (ctx, params, slot) => ({
        share: await shareInput(ctx, params, slot), nonce: randomNonce(),
      }),
      run: async (ctx, { share, nonce }, { algorithm }) =>
        createSchnorrPacket(ctx, share, { algorithm, nonce }),
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
