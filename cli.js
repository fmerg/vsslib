#!/usr/bin/node
const { Command, Option } = require('commander');
const {
  generateKey,
  shareKey,
  parseSharePacket,
} = require('./dist');
const {
  initGroup
} = require('./dist/backend');
const {
  shareSecret,
  SecretShare,
  parseFeldmannPacket,
  parsePedersenPacket,
  createPublicSharePacket,
  parsePublicSharePacket,
  reconstructPoint,
} = require('./dist/shamir');

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
    this.publicShare = undefined;
    this.pointShares = [];
    this.globalPublic = undefined;
  }
}

selectParty = (index, parties) => parties.filter(p => p.index == index)[0];


async function demoDKG(options) {
  const { system, encoding } = options;
  const nrShares = 10;
  const threshold = 3;
  // const scheme = "Feldmann";
  const scheme = "Pedersen";

  const ctx = initGroup(system);
  const publicBytes = (await ctx.randomPoint()).toBytes();

  const parties = [];
  for (let index = 1; index <= nrShares; index++) {
    parties.push(new ShareHolder(ctx, index));
  }

  // Sharing computation
  for (const party of parties) {
    console.time(`SHARING COMPUTATION ${party.index}`);
    party.originalSecret = await ctx.randomScalar();
    party.sharing = await shareSecret(ctx, nrShares, threshold, party.originalSecret);
    console.timeEnd(`SHARING COMPUTATION ${party.index}`);
  }


  // Sharing computation
  for (const party of parties) {
    console.time(`SHARE DISTRIBUTION ${party.index}`);
    if (scheme == "Feldmann") {
      const { packets, commitments } = await party.sharing.createFeldmannPackets();
      for (packet of packets) {
        const share = await parseFeldmannPacket(ctx, commitments, packet);
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
    party.share = new SecretShare(ctx, BigInt(0), party.index);
    for (const share of party.aggregates) {
      party.share.value = (party.share.value + share.value) % ctx.order;
    }
    party.publicShare = {
      value: await ctx.exp(party.share.value, ctx.generator),
      index: party.index,
    }
    console.timeEnd(`LOCAL SUMMATION ${party.index}`);
  }

  // Public key advertisement
  console.time("PUBLIC SHARE ADVERTISEMENT");
  for (sender of parties) {
    for (receiver of parties) {
      const nonce = await crypto.randomNonce();
      const packet = await createPublicSharePacket(sender.share, { nonce });
      const pointShare = await parsePublicSharePacket(ctx, packet, { nonce });
      receiver.pointShares.push(pointShare);
    }
  }
  console.timeEnd("PUBLIC SHARE ADVERTISEMENT");

  // Local computation of global public
  for (let party of parties) {
    party.globalPublic = await reconstructPoint(ctx, party.pointShares);
  }

  // Test correctness
  let targetPublic = ctx.neutral;
  for (party of parties) {
    const curr = await ctx.exp(party.originalSecret, ctx.generator);
    targetPublic = await ctx.operate(curr, targetPublic);
  }
  for (party of parties) {
    if (!(await party.globalPublic.equals(targetPublic))) {
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
