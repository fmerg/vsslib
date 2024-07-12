import { Command, Option } from 'commander';
import { parseDecimal } from './utils';
import {
  initBackend,
  extractPublic,
  isEqualPublic,
  parseSchnorrPacket,
  combinePublicShares,
  distributeSecret,
  extractPublicShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
  addSecrets,
  combinePublics,
} from 'vsslib';
import { Systems } from 'vsslib/enums';
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


const selectParty = (index, parties) => parties.filter(p => p.index == index)[0];

async function demo() {
  const { system, nrShares, threshold, verbose } = program.opts();

  const ctx = initBackend(system);

  // Public reference for Pedersen VSS Scheme
  const publicBytes = await ctx.randomPublic();

  // Involved parties initialization
  const parties = [];
  for (let index = 1; index <= nrShares; index++) {
    const party = new Party(ctx, index);
    parties.push(party);
  }

  // Computation of sharings
  for (let party of parties) {
    console.time(`SHARING ${party.index}`);
    const { secret, sharing } = await distributeSecret(ctx, nrShares, threshold);
    console.timeEnd(`SHARING ${party.index}`);
    party.originalSecret = secret ;
    party.originalPublic = await extractPublic(ctx, party.originalSecret);
    party.sharing = sharing;
  }

  // Distribution of packets
  for (let party of parties) {
    console.time(`DISTRIBUTION ${party.index}`);
    const { packets, commitments } = await party.sharing.createPedersenPackets(publicBytes);
    for (const packet of packets) {
      const recipient = selectParty(packet.index, parties);
      const { share, binding } = await parsePedersenPacket(
        ctx, commitments, publicBytes, packet
      );
      recipient.aggregates.push(share);
    }
    console.timeEnd(`DISTRIBUTION ${party.index}`);
  }

  // Local summation of received shares
  for (let party of parties) {
    console.time(`SUMMATION ${party.index}`);
    const localSum = await addSecrets(ctx, party.aggregates.map(s => s.value));
    console.timeEnd(`SUMMATION ${party.index}`);
    party.localSecretShare = { value: localSum, index: party.index };
    party.localPublicShare = await extractPublicShare(ctx, party.localSecretShare);
    // Public share advertisement
    for (const recipient of parties) {
      const nonce = await randomNonce();
      const packet = await createSchnorrPacket(ctx, party.localSecretShare, { nonce });
      const publicShare = await parseSchnorrPacket(ctx, packet, { nonce });
      recipient.publicShares.push(publicShare);
    }
  }

  // All parties should locally recover this global public
  const targetGlobalPublic = await combinePublics(ctx, parties.map(p => p.originalPublic));
  // Local recovery of combined public
  for (let party of parties) {
    party.globalPublic = await combinePublicShares(ctx, party.publicShares);
    // Check consistency
    const isConsistent = await isEqualPublic(ctx, party.globalPublic, targetGlobalPublic);
    if(!isConsistent) {
      throw new Error(`Inconsistency at location {party.index}`);
    }
    console.log(`ok ${party.index}`);
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
