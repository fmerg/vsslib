#!/usr/bin/node
const { Command, Option } = require('commander');
const {
  generateKey,
} = require('./dist');
const {
  serializePrivateKey,
  deserializePrivateKey,
  deserializePublicKey,
  serializePublicKey,
} = require('./dist/serializers');

const enums = require('./dist/enums')

const program = new Command();


async function doGenerateKey(options) {
  const { system, encoding } = options;
  const { privateKey, publicKey, ctx } = await generateKey(system);
  const privData = serializePrivateKey(privateKey, encoding);
  const privateBack = await deserializePrivateKey(privData);
  let arePrivEqual = await privateBack.equals(privateKey);
  if (!arePrivEqual) throw new Error("Private key serialization error");
  const pubData = serializePublicKey(publicKey, encoding);
  const publicBack = await deserializePublicKey(pubData);
  let areEqual = await publicBack.equals(publicKey);
  if (!areEqual) throw new Error("Public key serialization error");
  console.log('Key', {
    private: privData.value,
    public: pubData.value,
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

const encodingOption = new Option('-e, --encoding <encoding>', 'serialization encoding')
  .default(enums.Encodings.BASE64)
  .choices(Object.values(enums.Encodings));

program
  .command('generate')
  .description('Key generation')
  .addOption(systemOption)
  .addOption(encodingOption)
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
