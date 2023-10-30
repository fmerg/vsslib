#!/usr/bin/node
const { Command, Option } = require('commander');
const {
  Key,
  Public,
  key,
  elgamal,
} = require('./dist');

const enums = require('./dist/enums')

const program = new Command();

async function generateKey(options) {
  console.log(options);
  const priv = await key.generate(options.crypto);
  const pub = await priv.extractPublic();

  const privSerialized = priv.serialize();
  console.log(privSerialized);

  const privBack = key.deserialize(privSerialized);
  let areEqual = await privBack.isEqual(priv);
  console.log(areEqual);

  const pubSerialized = pub.serialize();
  console.log(pubSerialized);

  const pubBack = key.deserialize(pubSerialized);
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


const cryptoOption = new Option('-c, --crypto <label>', 'underlying cryptosystem')
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
