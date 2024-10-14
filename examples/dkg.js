import { Command, Option } from 'commander';
import { parseDecimal } from './utils';
import {
  initBackend,
  randomPublic,
  extractPublic,
  isEqualPublic,
  parseSchnorrPacket,
  combinePublicShares,
  shareSecret,
  extractPublicShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
  addSecrets,
  combinePublics,
} from 'vsslib';
import { Systems } from 'vsslib/enums';
import { randomNonce } from 'vsslib/random';

import { VssSchemes, Party, Combiner, selectParty } from './infra';

const program = new Command();

const DEFAULT_SYSTEM = Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

class DkgParty extends Party {
  constructor(ctx, index) {
    super(ctx, index);
    this.secret = undefined;
    this.sharing = undefined;
    this.aggregates = [];
    this.localSecret = undefined;
    this.localPublic = undefined;
    this.publicShares = [];
    this.globalPublic = undefined;
  }

  doShare = async (nrShares, threshold) => {
    console.time(`SHARING ${this.index}`);
    const { secret, sharing } = await shareSecret(this.ctx, nrShares, threshold);
    console.timeEnd(`SHARING ${this.index}`);
    this.secret = secret ;
    this.originalPublic = await extractPublic(this.ctx, this.secret);
    this.sharing = sharing;
  }

  doBroadcast = async (publicBytes) => {
    return this.sharing.createPedersenPackets(publicBytes);
  }

  doParseVss = async (commitments, publicBytes, packet) => {
    const { share, binding } = await parsePedersenPacket(
      this.ctx, commitments, publicBytes, packet
    );
    this.aggregates.push(share);
  }

  doLocal = async () => {
    console.time(`SUMMATION ${this.index}`);
    const sum = await addSecrets(this.ctx, this.aggregates.map(s => s.value));
    console.timeEnd(`SUMMATION ${this.index}`);
    this.localSecret = { value: sum, index: this.index };
    this.localPublic = await extractPublicShare(this.ctx, this.localSecret);
  }

  doAdvertise = async (nonce) => {
    return createSchnorrPacket(this.ctx, this.localSecret, { nonce });
  }

  doParseSchnorr = async (packet, nonce) => {
    const publicShare = await parseSchnorrPacket(this.ctx, packet, { nonce });
    this.publicShares.push(publicShare);
  }

  doGlobal = async () => {
    this.globalPublic = await combinePublicShares(this.ctx, this.publicShares);
  }
}


export function initGroup(ctx, nrParties) {
  const parties = [];
  for (let index = 1; index <= nrParties; index++) {
    const party = new DkgParty(ctx, index);
    parties.push(party);
  }
  return parties;
}


export async function runDKG(parties, nrShares, threshold, publicBytes) {
  for (let party of parties) {
    await party.doShare(nrShares, threshold);
  }

  for (let party of parties) {
    console.time(`DISTRIBUTION ${party.index}`);
    const { packets, commitments } = await party.doBroadcast(publicBytes);
    for (const packet of packets) {
      const recipient = selectParty(packet.index, parties);
      await recipient.doParseVss(commitments, publicBytes, packet);
    }
    console.timeEnd(`DISTRIBUTION ${party.index}`);
  }

  for (let party of parties) {
    party.doLocal();
  }

  for (let sender of parties) {
    for (const recipient of parties) {
      const nonce = await randomNonce();
      const packet = await sender.doAdvertise(nonce);
      await recipient.doParseSchnorr(packet, nonce);
    }
  }

  for (let party of parties) {
    await party.doGlobal();
  }

  return { globalPublic: parties[0].globalPublic };
}


async function demo() {
  const { system, nrShares, threshold, verbose } = program.opts();
  const ctx = initBackend(system);
  const parties = initGroup(ctx, nrShares);
  const publicBytes = await randomPublic(ctx);
  const { globalPublic } = await runDKG(parties, nrShares, threshold, publicBytes);

  // All parties should locally recover this global public
  const targetGlobalPublic = await combinePublics(ctx, parties.map(p => p.originalPublic));
  if (!(await isEqualPublic(ctx, globalPublic, targetGlobalPublic))) {
    throw new Error(`Inconsistent global public`);
  }
  for (let party of parties) {
    isConsistent = await isEqualPublic(ctx, party.globalPublic, globalPublic);
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
