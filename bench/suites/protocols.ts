/** End-to-end protocol flows: the computation of all parties, run in turn in
 * one process, i.e. the total work of a run without any networking */
import {
  shareSecret,
  derivePedersenBase,
  randomNonce,
  parseFeldmanPacket,
  parsePedersenPacket,
  combineSecretShares,
  createSchnorrPacket,
  recoverPublic,
  addSecrets,
} from 'vsslib';
import type { Nonces, SchnorrPacket, SecretShare } from 'vsslib';
import { Suite, defineCase } from '../types';
import { slotIndexes } from '../fixtures';


const suite: Suite = {
  module: 'protocols',
  cases: [
    // Dealing, distribution of the shares and reconstruction by a qualified set
    defineCase({
      name: 'sss',
      uses: ['nrShares', 'threshold'],
      setup: async (_, { nrShares, threshold }, slot) => slotIndexes(slot, nrShares, threshold),
      run: async (ctx, qualified, { nrShares, threshold }) => {
        const { sharing } = await shareSecret(ctx, nrShares, threshold);
        const shares = await sharing.getSecretShares();
        return combineSecretShares(ctx, qualified.map(index => shares[index - 1]), threshold);
      },
    }),
    // Dealing with commitments and verification by every shareholder
    defineCase({
      name: 'feldmanVss',
      uses: ['nrShares', 'threshold'],
      setup: async () => undefined,
      run: async (ctx, _, { nrShares, threshold }) => {
        const { sharing } = await shareSecret(ctx, nrShares, threshold);
        const { packets, commitments } = await sharing.createFeldmanPackets();
        for (const packet of packets) {
          await parseFeldmanPacket(ctx, commitments, packet, threshold);
        }
      },
    }),
    defineCase({
      name: 'pedersenVss',
      uses: ['nrShares', 'threshold'],
      setup: async (ctx) => derivePedersenBase(ctx, randomNonce()),
      run: async (ctx, pedersenBase, { nrShares, threshold }) => {
        const { sharing } = await shareSecret(ctx, nrShares, threshold);
        const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
        for (const packet of packets) {
          await parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold);
        }
      },
    }),
    // Every shareholder proves knowledge of its share, bound to its own nonce,
    // and the combiner verifies all proofs and interpolates
    defineCase({
      name: 'publicRecovery',
      uses: ['algorithm', 'nrShares', 'threshold'],
      setup: async (ctx, { nrShares, threshold }) =>
        (await shareSecret(ctx, nrShares, threshold)).sharing.getSecretShares(),
      run: async (ctx, shares, { threshold, algorithm }) => {
        const packets = [];
        const nonces: Nonces = {};
        for (const share of shares) {
          const nonce = randomNonce();
          nonces[share.index] = nonce;
          packets.push(await createSchnorrPacket(ctx, share, { algorithm, nonce }));
        }
        return recoverPublic(ctx, packets, threshold, { algorithm, nonces });
      },
    }),
    // Pedersen DKG: every party deals a sharing of its own secret, verifies
    // the packets addressed to it and sums them into its local share; then
    // every party publishes a Schnorr packet for its local share, and
    // recovers the global public key from all packets
    defineCase({
      name: 'dkg',
      uses: ['algorithm', 'nrShares', 'threshold'],
      setup: async (ctx) => derivePedersenBase(ctx, randomNonce()),
      run: async (ctx, pedersenBase, { nrShares, threshold, algorithm }) => {
        const received: Uint8Array[][] = Array.from({ length: nrShares }, () => []);
        for (let dealer = 1; dealer <= nrShares; dealer++) {
          const { sharing } = await shareSecret(ctx, nrShares, threshold);
          const { packets, commitments } = await sharing.createPedersenPackets(pedersenBase);
          for (const packet of packets) {
            const { share } = await parsePedersenPacket(
              ctx, commitments, pedersenBase, packet, threshold
            );
            received[share.index - 1].push(share.value);
          }
        }
        const localShares: SecretShare[] = [];
        for (let index = 1; index <= nrShares; index++) {
          localShares.push({ value: await addSecrets(ctx, received[index - 1]), index });
        }
        const packets: SchnorrPacket[] = [];
        const nonces: Nonces = {};
        for (const share of localShares) {
          const nonce = randomNonce();
          nonces[share.index] = nonce;
          packets.push(await createSchnorrPacket(ctx, share, { algorithm, nonce }));
        }
        let recovered: Uint8Array | undefined;
        for (let party = 1; party <= nrShares; party++) {
          ({ recovered } = await recoverPublic(ctx, packets, threshold, { algorithm, nonces }));
        }
        return { localShares, recovered };
      },
    }),
  ],
};

export default suite;
