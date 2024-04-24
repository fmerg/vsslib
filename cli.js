#!/usr/bin/node
const { Command, Option } = require('commander');
const {
  PrivateKey,
  PublicKey,
  key,
  plain,
} = require('./dist');

const schemes = require('./dist/schemes')

const program = new Command();

async function generateKey(options) {
  const { privateKey, publicKey } = await key.generate(options.system);

  const privSerialized = privateKey.serialize();
  console.log(privSerialized);
  const privateBack = await PrivateKey.deserialize(privSerialized);
  let areEqual = await privateBack.isEqual(privateKey);
  console.log(areEqual);

  const pubSerialized = publicKey.serialize();
  console.log(pubSerialized);
  const publicBack = await PublicKey.deserialize(pubSerialized);
  areEqual = await publicBack.isEqual(publicKey);
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


const cryptoOption = new Option('-s, --system <label>', 'underlying cryptosystem')
  .default(schemes.Systems.ED25519)
  .choices(Object.values(schemes.Systems));

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
