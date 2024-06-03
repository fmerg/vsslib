import { initGroup } from '../../src/backend';
import { Group, Point } from '../../src/backend/abstract';
import {
  SecretShare,
  ShamirSharing,
  PublicShare,
  shareSecret,
  parseFeldmannPacket,
  parsePedersenPacket,
  createPublicSharePacket,
  parsePublicSharePacket,
  reconstructPublic,
} from '../../src/shamir';
import { randomNonce } from '../../src/crypto';
import { resolveTestConfig } from '../environ';
import { isEqualBuffer } from '../helpers';

let { system, nrShares, threshold } = resolveTestConfig();

class ShareHolder<P extends Point> {
  index: number;
  originalSecret?: bigint;
  sharing?: ShamirSharing<P>;
  aggregates: SecretShare[];
  share?: SecretShare;
  publicShares: PublicShare[];
  localPublicShare?: PublicShare;
  globalPublic?: Uint8Array;

  constructor(ctx: Group<P>, index: number) {
    this.index = index;
    this.aggregates = [];
    this.publicShares = [];
  }
}


const selectParty = (index: number, parties: ShareHolder<Point>[]) => parties.filter(p => p.index == index)[0];


describe(`Distributed Key Generation (DKG) over ${system}`, () => {
  const ctx = initGroup(system);

  let parties: ShareHolder<Point>[];
  let publicBytes: Uint8Array;

  beforeEach(async () => {
    publicBytes = (await ctx.randomPoint()).toBytes();

    parties = [];
    for (let index = 1; index <= nrShares; index++) {
      parties.push(new ShareHolder(ctx, index));
    }

    for (let party of parties) {
      party.originalSecret = await ctx.randomScalar();
      party.sharing = await shareSecret(ctx, nrShares, threshold, party.originalSecret!);
    }
  })

  test('Feldmann - success', async () => {
    // Shares distribution
    for (const party of parties) {
      const { packets, commitments } = await party.sharing!.createFeldmannPackets();
      for (const packet of packets) {
        const share = await parseFeldmannPacket(ctx, commitments, packet);
        selectParty(share.index, parties).aggregates.push(share);
      }
    }

    // Local summation
    for (let party of parties) {
      party.share = { value: BigInt(0), index: party.index };
      for (const share of party.aggregates) {
        party.share.value = (party.share.value + share.value) % ctx.order;
      }
      party.localPublicShare = {
        value: await ctx.exp(party.share.value, ctx.generator),
        index: party.index,
      }
    }

    // Public key advertisement
    for (const sender of parties) {
      for (const receiver of parties) {
        const nonce = await randomNonce();
        const packet = await createPublicSharePacket(ctx, sender.share!, { nonce });
        const publicShare = await parsePublicSharePacket(ctx, packet, { nonce });
        receiver.publicShares.push(publicShare);
      }
    }

    // Local computation of global public
    for (let party of parties) {
      party.globalPublic = await reconstructPublic(ctx, party.publicShares);
    }

    // Test correctness
    let targetPublic = ctx.neutral;
    for (const party of parties) {
      const curr = await ctx.exp(party.originalSecret, ctx.generator);
      targetPublic = await ctx.operate(curr, targetPublic);
    }
    for (const party of parties) {
      expect(isEqualBuffer(party.globalPublic!, targetPublic.toBytes())).toBe(true);
    }
  });

  test('Pedersen - success', async () => {
    // Shares distribution
    for (const party of parties) {
      const { packets, commitments } = await party.sharing!.createPedersenPackets(
        publicBytes
      );
      for (const packet of packets) {
        const { share, binding } = await parsePedersenPacket(
          ctx, commitments, publicBytes, packet
        );
        selectParty(share.index, parties).aggregates.push(share);
      }
    }

    // Local summation
    for (let party of parties) {
      party.share = { value: BigInt(0), index: party.index };
      for (const share of party.aggregates) {
        party.share.value = (party.share.value + share.value) % ctx.order;
      }
      party.localPublicShare = {
        value: await ctx.exp(party.share.value, ctx.generator),
        index: party.index,
      }
    }

    // Public key advertisement
    for (const sender of parties) {
      for (const receiver of parties) {
        const nonce = await randomNonce();
        const packet = await createPublicSharePacket(ctx, sender.share!, { nonce });
        const publicShare = await parsePublicSharePacket(ctx, packet, { nonce });
        receiver.publicShares.push(publicShare);
      }
    }

    // Local computation of global public
    for (let party of parties) {
      party.globalPublic = await reconstructPublic(ctx, party.publicShares);
    }

    // Test correctness
    let targetPublic = ctx.neutral;
    for (const party of parties) {
      const curr = await ctx.exp(party.originalSecret, ctx.generator);
      targetPublic = await ctx.operate(curr, targetPublic);
    }
    for (const party of parties) {
      expect(isEqualBuffer(party.globalPublic!, targetPublic.toBytes())).toBe(true);
    }
  });
})
