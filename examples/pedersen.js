import { Command } from 'commander';
import { parseDecimal, parseCommaSeparatedDecimals } from './utils';
import {
  enums,
  initBackend,
  isKeypair,
  distributeSecret,
  parsePedersenPacket,
  createPublicPacket,
  recoverPublic
} from 'vsslib';

const DEFAULT_SYSTEM = enums.Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

const program = new Command();

async function demo() {
  let { system, nrShares: n, threshold: t, combine: qualified, verbose } = program.opts();
  const ctx = initBackend(system);

  // Involved parties agree on some public reference
  const publicBytes = await ctx.randomPublic();   // TODO: proper name

  // The dealer shares a secret and generates verifiable Pedersen packets
  const { secret: originalSecret, sharing } = await distributeSecret(ctx, n, t);
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
    const packet = await createPublicPacket(ctx, share);
    publicPackets.push(packet);
  }

  // Recover combined public from qualified packets
  qualified = qualified || Array.from({ length: t }, (_, i) => i + 1)
  const qualifiedPackets = publicPackets.filter(p => qualified.includes(p.index));
  const { recovered: recoveredPublic } = await recoverPublic(ctx, qualifiedPackets);
  console.log(await isKeypair(ctx, originalSecret, recoveredPublic));
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
