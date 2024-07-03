import { initBackend } from 'vsslib/backend';
import { Group, Point } from 'vsslib/backend';
import { SecretShare, ShamirSharing, PublicShare } from 'vsslib/dealer';
import {
  extractPublic,
  isEqualPublic,
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicPacket,
  parsePublicPacket,
  combinePublicShares,
} from 'vsslib';
import { randomNonce } from 'vsslib/crypto';
import { resolveTestConfig } from './environ';
import { mod, leInt2Buff } from 'vsslib/arith';

let { systems, nrShares, threshold } = resolveTestConfig();

class Party<P extends Point> {
  ctx: Group<P>;
  index: number;
  originalSecret?: Uint8Array;
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
    let parties = [];
    for (let index = 1; index <= nrShares; index++) {
      parties.push(new Party(ctx, index));
    }

    // Involved parties agree on some public reference
    const publicBytes = await ctx.randomPublic();

    // Computation of sharings
    for (let party of parties) {
      const { secret, sharing } = await distributeSecret(ctx, nrShares, threshold);
      party.originalSecret = secret ;
      party.sharing = sharing;
    }

    // Distribution of shares over the network
    for (const party of parties) {
      const { packets, commitments } = await party.sharing!.createPedersenPackets(publicBytes
      );
      for (const packet of packets) {
        const { share, binding } = await parsePedersenPacket(
          ctx, commitments, publicBytes, packet
        );
        selectParty(share.index, parties).aggregates.push(share);
      }
    }

    // Local summation of received shares
    for (let party of parties) {
      party.localSecretShare = { value: leInt2Buff(BigInt(0)), index: party.index };
      for (const share of party.aggregates) {
        const x = ctx.leBuff2Scalar(party.localSecretShare.value);
        const z = ctx.leBuff2Scalar(share.value);
        party.localSecretShare.value = leInt2Buff(mod(x + z, ctx.order));
      }
      party.localPublicShare = {
        value: await extractPublic(ctx, party.localSecretShare.value),
        index: party.index,
      }
    }

    // Public key advertisement
    for (const sender of parties) {
      for (const recipient of parties) {
        const nonce = await randomNonce();
        const packet = await createPublicPacket(ctx, sender.localSecretShare!, { nonce });
        const publicShare = await parsePublicPacket(ctx, packet, { nonce });
        recipient.publicShares.push(publicShare);
      }
    }

    // Local recovery of combined public
    for (let party of parties) {
      party.globalPublic = await combinePublicShares(ctx, party.publicShares);
    }

    // Test consistency
    let targetPublic = ctx.neutral;
    for (const party of parties) {
      const curr = await ctx.exp(
        ctx.generator,
        ctx.leBuff2Scalar(party.originalSecret!),
      );
      targetPublic = await ctx.operate(curr, targetPublic);
    }
    for (const party of parties) {
      expect(await isEqualPublic(ctx, party.globalPublic!, targetPublic.toBytes())).toBe(true);
    }
  });
})
