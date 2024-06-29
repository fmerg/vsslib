#!/usr/bin/node
const { Command, Option } = require('commander');
const {
  generateKey,
  parseSharePacket,
  combinePublicShares,
} = require('./dist');
const {
  initBackend
} = require('./dist/backend');
const {
  distributeSecret,
  SecretShare,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicSharePacket,
  parsePublicSharePacket,
} = require('./dist/dealer');
const {
  leInt2Buff,
  mod,
} = require('./dist/arith');

const enums = require('./dist/enums')
const crypto = require('./dist/crypto')

const program = new Command();


async function doGenerateKey(options) {
  const { system, encoding } = options;
  const { privateKey, publicKey, ctx } = await generateKey(system);
  console.log('Key', {
    private: privateKey.secret,
    public: publicKey.bytes,
    system,
    encoding,
  })

}

class ShareHolder {
  constructor(ctx, index) {
    this.index = index;
    this.originalSecret = undefined;
    this.sharing = undefined;
    this.aggregates = [];
    this.share = undefined;
    this.localPublicShare = undefined;
    this.publicShares = [];
    this.globalPublic = undefined;
  }
}

selectParty = (index, parties) => parties.filter(p => p.index == index)[0];

isEqualBuffer = (a, b) => {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++)
    if (a[i] != b[i]) return false;
  return true;
}


async function demoDKG(options) {
  const { system, encoding } = options;
  const nrShares = 10;
  const threshold = 5;
  // const scheme = "Feldman";
  const scheme = "Pedersen";

  const ctx = initBackend(system);
  const publicBytes = (await ctx.randomPoint()).toBytes();

  const parties = [];
  for (let index = 1; index <= nrShares; index++) {
    parties.push(new ShareHolder(ctx, index));
  }

  // Sharing computation
  for (const party of parties) {
    console.time(`SHARING COMPUTATION ${party.index}`);
    party.originalSecret = await ctx.randomSecret();
    party.sharing = await distributeSecret(ctx, nrShares, threshold, party.originalSecret);
    console.timeEnd(`SHARING COMPUTATION ${party.index}`);
  }


  // Sharing computation
  for (const party of parties) {
    console.time(`SHARE DISTRIBUTION ${party.index}`);
    if (scheme == "Feldman") {
      const { packets, commitments } = await party.sharing.createFeldmanPackets();
      for (packet of packets) {
        const share = await parseFeldmanPacket(ctx, commitments, packet);
        selectParty(share.index, parties).aggregates.push(share);
      }
    } else if (scheme == "Pedersen") {
      const { packets, commitments } = await party.sharing.createPedersenPackets(
        publicBytes
      );
      for (packet of packets) {
        const { share, binding } = await parsePedersenPacket(
          ctx, commitments, publicBytes, packet
        );
        selectParty(share.index, parties).aggregates.push(share);
      }
    }
    console.timeEnd(`SHARE DISTRIBUTION ${party.index}`);
  }

  // Local summation
  for (let party of parties) {
    console.time(`LOCAL SUMMATION ${party.index}`);
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
    console.timeEnd(`LOCAL SUMMATION ${party.index}`);
  }

  // Public key advertisement
  console.time("PUBLIC SHARE ADVERTISEMENT");
  for (sender of parties) {
    for (receiver of parties) {
      const nonce = await crypto.randomNonce();
      const packet = await createPublicSharePacket(ctx, sender.share, { nonce });
      const pubShare = await parsePublicSharePacket(ctx, packet, { nonce });
      receiver.publicShares.push(pubShare);
    }
  }
  console.timeEnd("PUBLIC SHARE ADVERTISEMENT");

  // Local computation of global public
  for (let party of parties) {
    party.globalPublic = await combinePublicShares(ctx, party.publicShares);
  }

  // Test correctness
  let targetPublic = ctx.neutral;
  for (party of parties) {
    const curr = await ctx.exp(
      ctx.generator,
      ctx.leBuff2Scalar(party.originalSecret),
    );
    targetPublic = await ctx.operate(curr, targetPublic);
  }
  for (party of parties) {
    if(!isEqualBuffer(party.globalPublic, targetPublic.toBytes())) {
      throw new Error(`Inconsistency at location {party.index}`);
    }
  }
}


async function sampleFunction(arg1, arg2, arg3, options) {
  console.log(program.opts());
  console.log(arg1);
  console.log(arg2);
  console.log(arg3);
  console.log(options);
}

program
  .name('vss')
  .description('Command line interface to vsslib')
  .version('1.0.0')
  .option('-v, --verbose', 'be verbose')
  .option('--some-option', 'some option')


const systemOption = new Option('-s, --system <system>', 'underlying cryptosystem')
  .default(enums.Systems.ED25519)
  .choices(Object.values(enums.Systems));

program
  .command('generate')
  .description('Key generation')
  .addOption(systemOption)
  .action(doGenerateKey)

program
  .command('dkg')
  .description('Distributed Key Generation (DKG) demo')
  .addOption(systemOption)
  .action(demoDKG)

program
  .command('sample')
  .description('Sample command for reference')
  .argument('<arg1>', 'First argument')
  .argument('<arg2>', 'Second argument')
  .argument('[arg3]', 'Third argument')
  .option('-a, --alpha <option1>', 'Alpha option', 'ALPHA')
  .option('-b, --beta <option2>', 'Beta option')
  .requiredOption('-g, --gamma <option3>', 'Gamma option')
  .action(sampleFunction)


program.parse();
