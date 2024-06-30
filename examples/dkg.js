#!/usr/bin/node

const { Command, Option } = require('commander');
const commander = require('commander');
const {
  initBackend,
  parsePublicPacket,
  combinePublicShares,
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicPacket,
} = require('../dist');
const { Systems } = require('../dist/enums');
const { leInt2Buff, mod } = require('../dist/arith');
const enums = require('../dist/enums')
const crypto = require('../dist/crypto')
const program = new Command();

const DEFAULT_SYSTEM = Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

const isEqualBuffer = (a, b) => {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++)
    if (a[i] != b[i]) return false;
  return true;
}

const parseDecimal = (value) => {
  const parsedValue = parseInt(value, 10);
  if (isNaN(parsedValue)) {
    throw new commander.InvalidArgumentError('Not a number.');
  }
  return parsedValue;
}

class ShareHolder {
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

const initShareHolders = (ctx, nrShares) => {
  const shareholders = [];
  for (let index = 1; index <= nrShares; index++) {
    shareholders.push(new ShareHolder(ctx, index));
  }
  return shareholders;
}

const selectParty = (index, shareholders) => shareholders.filter(p => p.index == index)[0];

async function demo() {
  const { system, nrShares, threshold, verbose } = program.opts();

  const ctx = initBackend(system);
  const publicBytes = await ctx.randomPublic();
  const shareholders = initShareHolders(ctx, nrShares);

  // Sharing computation
  for (const shareholder of shareholders) {
    console.time(`SHARING COMPUTATION ${shareholder.index}`);
    shareholder.originalSecret = await ctx.randomSecret();
    shareholder.sharing = await distributeSecret(ctx, nrShares, threshold, shareholder.originalSecret);
    console.timeEnd(`SHARING COMPUTATION ${shareholder.index}`);
  }

  // Shares distribution
  for (const shareholder of shareholders) {
    console.time(`SHARE DISTRIBUTION ${shareholder.index}`);
    const { packets, commitments } = await shareholder.sharing.createPedersenPackets(publicBytes);
    for (packet of packets) {
      const { share, binding } = await parsePedersenPacket(ctx, commitments, publicBytes, packet);
      selectParty(share.index, shareholders).aggregates.push(share);
    }
    console.timeEnd(`SHARE DISTRIBUTION ${shareholder.index}`);
  }

  // Local summation
  for (let shareholder of shareholders) {
    console.time(`LOCAL SUMMATION ${shareholder.index}`);
    shareholder.localSecretShare = { value: leInt2Buff(BigInt(0)), index: shareholder.index };
    for (const share of shareholder.aggregates) {
      const x = ctx.leBuff2Scalar(shareholder.localSecretShare.value);
      const z = ctx.leBuff2Scalar(share.value);
      shareholder.localSecretShare.value = leInt2Buff(mod(x + z, ctx.order));
    }
    shareholder.localPublicShare = {
      value: (
        await ctx.exp(
          ctx.generator,
          ctx.leBuff2Scalar(shareholder.localSecretShare.value),
        )
      ).toBytes(),
      index: shareholder.index,
    }
    console.timeEnd(`LOCAL SUMMATION ${shareholder.index}`);
  }

  // Public key advertisement
  console.time("PUBLIC SHARE ADVERTISEMENT");
  for (sender of shareholders) {
    for (recipient of shareholders) {
      const nonce = await crypto.randomNonce();
      const packet = await createPublicPacket(ctx, sender.localSecretShare, { nonce });
      const pubShare = await parsePublicPacket(ctx, packet, { nonce });
      recipient.publicShares.push(pubShare);
    }
  }
  console.timeEnd("PUBLIC SHARE ADVERTISEMENT");

  // Local computation of global public
  for (let shareholder of shareholders) {
    shareholder.globalPublic = await combinePublicShares(ctx, shareholder.publicShares);
  }

  // Test correctness
  let targetPublic = ctx.neutral;
  for (shareholder of shareholders) {
    const curr = await ctx.exp(
      ctx.generator,
      ctx.leBuff2Scalar(shareholder.originalSecret),
    );
    targetPublic = await ctx.operate(curr, targetPublic);
  }
  for (shareholder of shareholders) {
    if(!isEqualBuffer(shareholder.globalPublic, targetPublic.toBytes())) {
      throw new Error(`Inconsistency at location {shareholder.index}`);
    }
  }
}

program
  .name('node dkg.js')
  .description('Distributed Key Generation (DKG) - demo')
  .option('-s, --system <SYSTEM>', 'underlying cryptosystem', DEFAULT_SYSTEM)
  .option('-n, --nr-shares <NR>', 'number of shareholders', parseDecimal, DEFAULT_NR_SHARES)
  .option('-t, --threshold <THRESHOLD>', 'threshold parameter', parseDecimal, DEFAULT_THRESHOLD)
  .option('-v, --verbose', 'be verbose')

program
  .command('run')
  .description('Run demo DKG (Distributed Key Generation)')
  .action(demo)


program.parse();
