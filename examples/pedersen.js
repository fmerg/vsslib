import { Command } from 'commander';
import {
  parseDecimal,
  parseCommaSeparatedDecimals,
  Party,
  Combiner,
  selectParty,
} from './utils';
import {
  initBackend,
  randomPublic,
  isKeypair,
  distributeSecret,
  parsePedersenPacket,
  createSchnorrPacket,
  recoverPublic,
  InvalidSecretShare,
  InvalidPublicShare,
} from 'vsslib';
import { Systems } from 'vsslib/enums';

const DEFAULT_SYSTEM = Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

const program = new Command();

async function demo() {
  let { system, nrShares: n, threshold: t, combine: qualified, verbose } = program.opts();
  qualified = qualified || Array.from({ length: t }, (_, i) => i + 1)

  // Cryptosystem setup
  const ctx = initBackend(system);

  // Involved parties agree on some public reference
  const publicBytes = await randomPublic(ctx);   // TODO: proper name
  //
  // Initialization of shareholders
  const parties = [];
  for (let index = 1; index <= n; index++) {
    const party = new Party(ctx, index);
    parties.push(party);
  }

  // VSS phase ----------------------------------------------------------------

  // The dealer shares some uniformly sampled secret
  const { secret: originalSecret, sharing } = await distributeSecret(ctx, n, t);
  // The dealer generates Pedersen commitments and verifiable packets for the
  // secret shares
  const { commitments, packets } = await sharing.createPedersenPackets(publicBytes);

  // At this point, the dealer broadcasts the commitments and sends each packet to the
  // respective shareholder in private

  // Shareholders verify the received packets and extract their respective share
  for (const packet of packets) {
    const recipient = selectParty(packet.index, parties);
    try {
      const { share } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
      // Store the retrieved share locally
      recipient.share = share;
    } catch (err) {
      if (err instanceof InvalidSecretShare) {
        // The recipient shareholder rejects the packet and follows some policy
      } else {
        throw err;
      }
    }
  }

  // Public recovery phase ----------------------------------------------------

  // Initialization of combiner
  const combiner = new Combiner(ctx);

  // A coalition of shareholders create Schnorr packets for their respective secret shares and
  // send them to the combiner
  for (const sender of parties.filter(p => qualified.includes(p.index))) {
    const packet = await createSchnorrPacket(sender.ctx, sender.share);
    combiner.aggreagated.push(packet);
  }

  // The combiner verifies the received Schnorr packets, extracts the included
  // public shares and applies interpolation in the exponent in order to
  // recover the public counterpart of the original secret
  try {
    const { recovered: recoveredPublic } = await recoverPublic(ctx, combiner.aggreagated);
    // Check consistency with original secret
    const ok = await isKeypair(ctx, originalSecret, recoveredPublic);
    console.log({ ok });
  } catch (err) {
    if (err instanceof InvalidPublicShare) {
      // The aborts and follows some policy
    } else {
      throw err;
    }
  }
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
