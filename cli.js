#!/usr/bin/node
const { Command, Option } = require('commander');
const {
  Key,
  Public,
  elgamal,
} = require('./dist');

const enums = require('./dist/enums')


const program = new Command();


async function generateKey(options) {
  const key = await Key.generate({ crypto: options.crypto });
  const pub = await key.extractPublic();

  const keySerialized = await key.serialize();
  console.log(keySerialized);

  const keyBack = await Key.deserialize(keySerialized, { crypto: options.crypto });
  let areEqual = await keyBack.isEqual(key);
  console.log(areEqual);

  const pubSerialized = await pub.serialize();
  console.log(pubSerialized);

  const pubBack = await Public.deserialize(pubSerialized, { crypto: options.crypto });
  areEqual = await pubBack.isEqual(pub);
  console.log(areEqual);
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


const cryptoOption = new Option('-c, --crypto <label>', 'underlying ccypto')
  .default(enums.Systems.ED25519)
  .choices(Object.values(enums.Systems));

program
  .command('generate')
  .description('Key generation')
  .addOption(cryptoOption)
  .option('-d, --dump <filepath>', 'Dump key in the provided file')
  .action(generateKey)

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
