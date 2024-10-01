import { Command } from 'commander';
import { parseDecimal, parseCommaSeparatedDecimals } from './utils';
import { VssSchemes, Party, Combiner, selectParty } from './infra';
import {
  initBackend,
  randomPublic,
  isKeypair,
  shareSecret,
  parseFeldmanPacket,
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


export async function runVSS(ctx, nrShares, threshold, scheme) {
  const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
  let publicBytes;
  if (scheme == VssSchemes.PEDERSEN) {
      publicBytes = await randomPublic(ctx);
  }
  const { commitments, packets } = (scheme == VssSchemes.FELDMAN) ?
    await sharing.createFeldmanPackets() :
    await sharing.createPedersenPackets(publicBytes);
  return { secret, sharing, commitments, publicBytes, packets};
}

class VssParty extends Party {
  consumeVssPacket = async (packet, commitments, publicBytes) => {
    try {
      const { share } = !publicBytes ?
        await parseFeldmanPacket(this.ctx, commitments, packet) :
        await parsePedersenPacket(this.ctx, commitments, publicBytes, packet);
      this.share = share;
    } catch (err) {
      if (err instanceof InvalidSecretShare) {
      } else {
        throw err;
      }
    }
  }
}

export function initGroup(ctx, nrParties) {
  const parties = [];
  for (let index = 1; index <= nrParties; index++) {
    const party = new VssParty(ctx, index);
    parties.push(party);
  }
  return parties;
}

async function demo() {
  let { scheme, system, nrShares: n, threshold: t, combine: qualified, verbose } = program.opts();
  qualified = qualified || Array.from({ length: t }, (_, i) => i + 1);

  const ctx = initBackend(system);

  const parties = initGroup(ctx, n);


  // VSS phase ----------------------------------------------------------------

  const { secret, commitments, publicBytes, packets } = await runVSS(ctx, n, t, scheme);

  // At this point, the dealer broadcasts the commitments and sends each packet to the
  // respective shareholder in private

  // Shareholders verify the received packets and extract their respective share
  for (const packet of packets) {
    const recipient = selectParty(packet.index, parties);
    await recipient.consumeVssPacket(packet, commitments, publicBytes);
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
    const ok = await isKeypair(ctx, secret, recoveredPublic);
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
  .name('node feldman.js')
  .description('Verifiable Secret Sharing (VSS) - demo')
  .option('--scheme <SCHEME>', 'VSS Scheme to use. Must be either \"feldman\" or \"pedersen\"', VssSchemes.DEFAULT)
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
