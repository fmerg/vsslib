#!/usr/bin/node

const { Command } = require('commander');
const commander = require('commander');

const program = new Command();

const { initBackend, distributeSecret, combineSecretShares, combinePublicShares, enums } = require('../dist');

const DEFAULT_SYSTEM = enums.Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

const isEqualBuffer = (a, b) => {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++)
    if (a[i] != b[i]) return false;
  return true;
}

const isEqualSecret = (ctx, lhs, rhs) => ctx.leBuff2Scalar(lhs) == ctx.leBuff2Scalar(rhs);

const parseDecimal = (value) => {
  const parsedValue = parseInt(value, 10);
  if (isNaN(parsedValue)) {
    throw new commander.InvalidArgumentError('Not a number.');
  }
  return parsedValue;
}
const parseCommaSeparatedDecimals = (values) => {
  return values.split(',').map(v => parseDecimal(v))
}

async function demo() {
  // Parse cli options
  let { system, nrShares: n, threshold: t, combine: qualifiedIndexes, verbose } = program.opts();

  // Generate and share secret
  const ctx = initBackend(system);
  const secret = await ctx.randomSecret();
  const sharing = await distributeSecret(ctx, n, t, secret);

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
  console.log(isEqualBuffer(combinedPublic,
    (await ctx.exp(ctx.generator, ctx.leBuff2Scalar(secret))).toBytes())
  );
}

program
  .name('node shamir.js')
  .description('shamir secret sharing (raw) - demo')
  .option('-s, --system <SYSTEM>', 'underlying cryptosystem', DEFAULT_SYSTEM)
  .option('-n, --nr-shares <NR>', 'number of shareholders', parseDecimal, DEFAULT_NR_SHARES)
  .option('-t, --threshold <THRESHOLD>', 'threshold parameter', parseDecimal, DEFAULT_THRESHOLD)
  .option('-c, --combine <INDEXES>', 'qualified indexes', parseCommaSeparatedDecimals)
  .option('-v, --verbose', 'be verbose')

program
  .command('run')
  .description('Run raw SSS (Shamir Secret Sharing) and recover combined keys without verification')
  .action(demo)


program.parse();
