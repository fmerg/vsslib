import { initGroup } from '../../src/backend';
import { Group, Point } from '../../src/backend/abstract';
import {
  SecretShare,
  ShamirSharing,
  PublicShare,
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicSharePacket,
  parsePublicSharePacket,
  reconstructPublic,
} from '../../src/shamir';
import { randomNonce } from '../../src/crypto';
import { resolveTestConfig } from '../environ';
import { isEqualBuffer } from '../utils';
import { mod, leInt2Buff } from '../../src/arith';

let { systems, nrShares, threshold } = resolveTestConfig();

class ShareHolder<P extends Point> {
  ctx: Group<P>;
  index: number;
  originalSecret?: Uint8Array;
  sharing?: ShamirSharing<P>;
  aggregates: SecretShare[];
  share?: SecretShare;
  publicShares: PublicShare[];
  localPublicShare?: PublicShare;
  globalPublic?: Uint8Array;

  constructor(ctx: Group<P>, index: number) {
    this.ctx = ctx;
    this.index = index;
    this.aggregates = [];
    this.publicShares = [];
  }
}


const selectParty = (index: number, parties: ShareHolder<Point>[]) => parties.filter(p => p.index == index)[0];


describe('Distributed Key Generation (DKG)', () => {
  it.each(systems)('over %s', async (system) => {
    const ctx = initGroup(system);
    const publicBytes = (await ctx.randomPoint()).toBytes();
    let parties = [];
    for (let index = 1; index <= nrShares; index++) {
      parties.push(new ShareHolder(ctx, index));
    }

    for (let party of parties) {
      party.originalSecret = await ctx.randomSecret();
      party.sharing = await distributeSecret(ctx, nrShares, threshold, party.originalSecret!);
    }

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
      party.share = { value: leInt2Buff(BigInt(0)), index: party.index };
      for (const share of party.aggregates) {
        const x = ctx.leBuff2Scalar(party.share.value);
        const z = ctx.leBuff2Scalar(share.value);
        party.share.value = leInt2Buff(mod(x + z, ctx.order));
      }
      party.localPublicShare = {
        value: (
          await ctx.exp(
            ctx.generator,
            ctx.leBuff2Scalar(party.share.value),
          )
        ).toBytes(),
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
      const curr = await ctx.exp(
        ctx.generator,
        ctx.leBuff2Scalar(party.originalSecret),
      );
      targetPublic = await ctx.operate(curr, targetPublic);
    }
    for (const party of parties) {
      expect(isEqualBuffer(party.globalPublic!, targetPublic.toBytes())).toBe(true);
    }
  });
})
