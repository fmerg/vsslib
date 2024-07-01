#!/usr/bin/node

const { Command } = require('commander');
const {
  isEqualSecret,
  isEqualBuffer,
  parseDecimal,
  parseCommaSeparatedDecimals,
} = require('./utils');
const {
  enums,
  initBackend,
  distributeSecret,
  combineSecretShares,
  combinePublicShares,
} = require('../dist');

const DEFAULT_SYSTEM = enums.Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

const program = new Command();

async function demo() {
  // Parse cli options
  let { system, nrShares: n, threshold: t, combine: qualifiedIndexes, verbose } = program.opts();

  // Generate and share secret
  const ctx = initBackend(system);
  const { secret, sharing } = await distributeSecret(ctx, n, t);

  qualifiedIndexes = qualifiedIndexes || Array.from({ length: t }, (_, i) => i + 1)
  // Combine qualified secret shares to recover original secret
  const secretShares = await sharing.getSecretShares();
  const combinedSecret = await combineSecretShares(ctx, secretShares.filter(
    share => qualifiedIndexes.includes(share.index)
  ));
  console.log(isEqualSecret(ctx, combinedSecret, secret));

  // Combine qualified public shares to recover original public
  const publicShares = await sharing.getPublicShares();
  const combinedPublic = await combinePublicShares(ctx, publicShares.filter(
    share => qualifiedIndexes.includes(share.index)
  ));
  console.log(isEqualBuffer(
    combinedPublic,
    (await ctx.exp(ctx.generator, ctx.leBuff2Scalar(secret))).toBytes())  // TODO
  );
}

program
  .name('node shamir.js')
  .description('Shamir Secret Sharing (raw SSS) - demo')
  .option('-s, --system <SYSTEM>', 'Underlying cryptosystem', DEFAULT_SYSTEM)
  .option('-n, --nr-shares <NR>', 'Number of shareholders', parseDecimal, DEFAULT_NR_SHARES)
  .option('-t, --threshold <THRESHOLD>', 'Threshold paramer', parseDecimal, DEFAULT_THRESHOLD)
  .option('-c, --combine <INDEXES>', 'Qualified indexes', parseCommaSeparatedDecimals)
  .option('-v, --verbose', 'be verbose')

program
  .command('run')
  .description('Run raw SSS and recover combined keys')
  .action(demo)


program.parse();
