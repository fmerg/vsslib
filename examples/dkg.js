import { Command, Option } from 'commander';
import { parseDecimal } from './utils';
import {
  initBackend,
  extractPublic,
  isEqualPublic,
  parsePublicPacket,
  combinePublicShares,
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicPacket,
} from 'vsslib';
import { Systems } from 'vsslib/enums';
import { leInt2Buff, mod } from 'vsslib/arith';
import { randomNonce } from 'vsslib/crypto';

const program = new Command();

const DEFAULT_SYSTEM = Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

class Party {
  constructor(ctx, index) {
    this.index = index;
    this.originalSecret = undefined;
    this.sharing = undefined;
    this.aggregates = [];
    this.localSecretShare = undefined;
    this.localPublicShare = undefined;
    this.publicShares = [];
    this.globalPublic = undefined;
  }
}


async function demo() {
  const { system, nrShares, threshold, verbose } = program.opts();
  const ctx = initBackend(system);
  const parties = [];
  for (let index = 1; index <= nrShares; index++) {
    parties.push(new Party(ctx, index));
  }

  // Involved parties agree on some public reference
  const publicBytes = await ctx.randomPublic();

  // Computation of sharings
  for (const party of parties) {
    console.time(`SHARING COMPUTATION ${party.index}`);
    const { secret, sharing } = await distributeSecret(ctx, nrShares, threshold);
    console.timeEnd(`SHARING COMPUTATION ${party.index}`);
    party.originalSecret = secret;
    party.sharing = sharing;
  }

  // Distribution of shares over the network
  const selectParty = (index, parties) => parties.filter(p => p.index == index)[0];
  for (const party of parties) {
    console.time(`SHARE DISTRIBUTION ${party.index}`);
    const { packets, commitments } = await party.sharing.createPedersenPackets(publicBytes);
    for (packet of packets) {
      const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
      selectParty(share.index, parties).aggregates.push(share);
    }
    console.timeEnd(`SHARE DISTRIBUTION ${party.index}`);
  }

  // Local summation of received shares
  for (let party of parties) {
    console.time(`LOCAL SUMMATION ${party.index}`);
    party.localSecretShare = { value: leInt2Buff(BigInt(0)), index: party.index };
    // TODO: // add secrets
    for (const share of party.aggregates) {
      const x = ctx.leBuff2Scalar(party.localSecretShare.value);
      const z = ctx.leBuff2Scalar(share.value);
      party.localSecretShare.value = leInt2Buff(mod(x + z, ctx.order));
    }
    // TODO: extractPublicShare
    party.localPublicShare = {
      value: await extractPublic(ctx, party.localSecretShare.value),
      index: party.index,
    }
    console.timeEnd(`LOCAL SUMMATION ${party.index}`);
  }

  // Public key advertisement
  console.time("PUBLIC SHARE ADVERTISEMENT");
  for (sender of parties) {
    for (recipient of parties) {
      const nonce = await randomNonce();
      const packet = await createPublicPacket(ctx, sender.localSecretShare, { nonce });
      const pubShare = await parsePublicPacket(ctx, packet, { nonce });
      recipient.publicShares.push(pubShare);
    }
  }
  console.timeEnd("PUBLIC SHARE ADVERTISEMENT");

  // Local computation of global public
  for (let party of parties) {
    party.globalPublic = await combinePublicShares(ctx, party.publicShares);
  }

  // Test correctness
  let targetPublic = ctx.neutral;
  // TODO: mulitply publics
  for (party of parties) {
    const curr = await ctx.exp(
      ctx.generator,
      ctx.leBuff2Scalar(party.originalSecret),
    );
    targetPublic = await ctx.operate(targetPublic, curr);
  }
  for (party of parties) {
    if(!isEqualPublic(ctx, party.globalPublic, targetPublic.toBytes())) {
      throw new Error(`Inconsistency at location {party.index}`);
    }
  }
}

program
  .name('node dkg.js')
  .description('Distributed Key Generation (DKG) - demo')
  .option('-s, --system <SYSTEM>', 'Underlying cryptosystem', DEFAULT_SYSTEM)
  .option('-n, --nr-shares <NR>', 'Number of parties', parseDecimal, DEFAULT_NR_SHARES)
  .option('-t, --threshold <THRESHOLD>', 'Threshold paramer', parseDecimal, DEFAULT_THRESHOLD)
  .option('-v, --verbose', 'be verbose')

program
  .command('run')
  .description('Run demo DKG (Distributed Key Generation) and recover combined public')
  .action(demo)


program.parse();
