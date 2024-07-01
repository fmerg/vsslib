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
  parsePedersenPacket,
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

  const ctx = initBackend(system);
  // Involved parties agree on some public reference
  const publicBytes = await ctx.randomPublic();   // TODO: proper name

  // The dealer shares a secret and generates verifiable Pedersen packets
  const { secret, sharing } = await distributeSecret(ctx, n, t);
  const { commitments, packets } = await sharing.createPedersenPackets(publicBytes);

  // At this point, the dealer brodcasts the commitments and sends each packet to the
  // respective shareholder

  // TODO: Consider decoupling binding and send it from a different channel

  // Every shareholders verifies the received Pedersen packet and extracts
  // the respective share
  const secretShares = [];
  for (const packet of packets) {
    const { share } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
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
  .name('node pedersen.js')
  .description('Pedersen Verifiable Secret Sharing (Pedersen VSS)- demo')
  .option('-s, --system <SYSTEM>', 'Underlying cryptosystem', DEFAULT_SYSTEM)
  .option('-n, --nr-shares <NR>', 'Number of shareholders', parseDecimal, DEFAULT_NR_SHARES)
  .option('-t, --threshold <THRESHOLD>', 'Threshold paramer', parseDecimal, DEFAULT_THRESHOLD)
  .option('-c, --combine <INDEXES>', 'Qualified indexes', parseCommaSeparatedDecimals)
  .option('-v, --verbose', 'be verbose')

program
  .command('run')
  .description('Run Pedersen VSS and verifiably recover combined public')
  .action(demo)


program.parse();
