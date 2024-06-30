#!/usr/bin/node

const { Command, Option } = require('commander');
const {
  initBackend,
  generateKey,
  parsePublicPacket,
  combinePublicShares,
  distributeSecret,
  parseFeldmanPacket,
  parsePedersenPacket,
  createPublicPacket,
} = require('./dist');
const { leInt2Buff, mod } = require('./dist/arith');

const enums = require('./dist/enums')
const crypto = require('./dist/crypto')

const program = new Command();


async function doGenerateKey(options) {
  const { system, encoding } = options;
  const ctx = initBackend(system);
  const { privateKey, publicKey } = await generateKey(ctx);
  console.log('Key', {
    private: privateKey.secret,
    public: publicKey.bytes,
    system,
    encoding,
  })

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
