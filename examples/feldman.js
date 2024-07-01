#!/usr/bin/node

const { Command } = require('commander');
const {
  isEqualSecret,
  isEqualBuffer,
  parseDecimal,
  parseCommaSeparatedDecimals,
} = require('./utils');
const {
  enums,
  initBackend,
  distributeSecret,
  parseFeldmanPacket,
  createPublicPacket,
  recoverPublic
} = require('../dist');

const DEFAULT_SYSTEM = enums.Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

const program = new Command();

async function demo() {
  // Parse cli options
  let { system, nrShares: n, threshold: t, combine: qualifiedIndexes, verbose } = program.opts();

  // The dealer shares a secret and generates verifiable Feldman packets
  const ctx = initBackend(system);
  const { secret, sharing } = await distributeSecret(ctx, n, t);
  const { commitments, packets } = await sharing.createFeldmanPackets();

  // At this point, the dealer brodcasts the commitments and sends each packet to the
  // respective shareholder

  // Every shareholders verifies the received Feldman packet and extracts
  // the respective share
  const secretShares = [];
  for (const packet of packets) {
    const share = await parseFeldmanPacket(ctx, commitments, packet);
    secretShares.push(share);
  }

  // Every shareholder creates a Shnorr proof for their respective secret share
  const publicPackets = [];
  for (const share of secretShares) {
    const packet = await createPublicPacket(ctx, share);  // TODO: nonce
    publicPackets.push(packet);
  }

  // Recover combined public from qualified packets
  qualifiedIndexes = qualifiedIndexes || Array.from({ length: t }, (_, i) => i + 1)
  const { recovered } = await recoverPublic(ctx, publicPackets.filter(
    packet => qualifiedIndexes.includes(packet.index)
  ));
  console.log(isEqualBuffer(
    recovered,
    (await ctx.exp(ctx.generator, ctx.leBuff2Scalar(secret))).toBytes())  // TODO
  );
}

program
  .name('node feldman.js')
  .description('Feldman Verifiable Secret Sharing (Feldman VSS) - demo')
  .option('-s, --system <SYSTEM>', 'Underlying cryptosystem', DEFAULT_SYSTEM)
  .option('-n, --nr-shares <NR>', 'Number of shareholders', parseDecimal, DEFAULT_NR_SHARES)
  .option('-t, --threshold <THRESHOLD>', 'Threshold paramer', parseDecimal, DEFAULT_THRESHOLD)
  .option('-c, --combine <INDEXES>', 'Qualified indexes', parseCommaSeparatedDecimals)
  .option('-v, --verbose', 'be verbose')

program
  .command('run')
  .description('Run Feldman VSS and verifiably recover combined public')
  .action(demo)


program.parse();
