import { initBackend } from 'vsslib/backend';
import { Group, Point } from 'vsslib/backend';
import { SecretShare, ShamirSharing, PublicShare } from 'vsslib/dealer';
import {
  randomPublic,
  extractPublic,
  isEqualPublic,
  shareSecret,
  extractPublicShare,
  parsePedersenPacket,
  createSchnorrPacket,
  parseSchnorrPacket,
  combinePublicShares,
  addSecrets,
  combinePublics,
} from 'vsslib';
import { randomNonce } from 'vsslib/random';
import { resolveTestConfig } from './environ';

let { systems, nrShares, threshold } = resolveTestConfig();

class Party<P extends Point> {
  ctx: Group<P>;
  index: number;
  originalSecret?: Uint8Array;
  originalPublic?: Uint8Array;
  sharing?: ShamirSharing<P>;
  aggregates: SecretShare[];
  localSecretShare?: SecretShare;
  localPublicShare?: PublicShare;
  publicShares: PublicShare[];
  globalPublic?: Uint8Array;

  constructor(ctx: Group<P>, index: number) {
    this.ctx = ctx;
    this.index = index;
    this.aggregates = [];
    this.publicShares = [];
  }
}


const selectParty = <P extends Point>(index: number, parties: Party<P>[]) =>
  parties.filter(p => p.index == index)[0];


describe('Distributed Key Generation (DKG)', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initBackend(system);

    // Public reference for Pedersen VSS Scheme
    const publicBytes = await randomPublic(ctx);

    // Involved parties initialization
    const parties = [];
    for (let index = 1; index <= nrShares; index++) {
      const party = new Party(ctx, index);
      parties.push(party);
    }

    // Computation of sharings
    for (let party of parties) {
      const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
      party.originalSecret = secret ;
      party.originalPublic = await extractPublic(ctx, party.originalSecret);
      party.sharing = sharing;
      const { packets, commitments } = await party.sharing.createPedersenPackets(publicBytes);
      // Distribution of shares over the network
      for (const packet of packets) {
        const recipient = selectParty(packet.index, parties);
        const { share, binding } = await parsePedersenPacket(
          ctx, commitments, publicBytes, packet
        );
        recipient.aggregates.push(share);
      }
    }

    // Local summation of received shares
    for (let party of parties) {
      const localSum = await addSecrets(ctx, party.aggregates.map(s => s.value));
      party.localSecretShare = { value: localSum, index: party.index };
      party.localPublicShare = await extractPublicShare(ctx, party.localSecretShare);
      // Public share advertisement
      for (const recipient of parties) {
        const nonce = await randomNonce();
        const packet = await createSchnorrPacket(ctx, party.localSecretShare!, { nonce });
        const publicShare = await parseSchnorrPacket(ctx, packet, { nonce });
        recipient.publicShares.push(publicShare);
      }
    }

    // All parties should locally recover this global public
    const targetGlobalPublic = await combinePublics(ctx, parties.map(p => p.originalPublic!));
    // Local recovery of combined public
    for (let party of parties) {
      party.globalPublic = await combinePublicShares(ctx, party.publicShares);
      // Check consistency
      expect(await isEqualPublic(ctx, party.globalPublic, targetGlobalPublic)).toBe(true);
    }
  });
})
