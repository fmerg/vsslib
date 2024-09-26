import { Command } from 'commander';
import { parseDecimal, parseCommaSeparatedDecimals } from './utils.js';
import {
  Systems,
  initBackend,
  isEqualSecret,
  isKeypair,
  shareSecret,
  combineSecretShares,
  combinePublicShares,
} from 'vsslib';

const DEFAULT_SYSTEM = Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;

const program = new Command();

async function demo() {
  let { system, nrShares: n, threshold: t, combine: qualified, verbose } = program.opts();
  qualified = qualified || Array.from({ length: t }, (_, i) => i + 1);

  const ctx = initBackend(system);

  const { secret, sharing } = await shareSecret(ctx, n, t);

  // Combine secret shares
  const secretShares = (await sharing.getSecretShares()).filter(s => qualified.includes(s.index));
  const combinedSecret = await combineSecretShares(ctx, secretShares);
  console.log(await isEqualSecret(ctx, combinedSecret, secret));

  // Combine public shares
  const publicShares = (await sharing.getPublicShares()).filter(s => qualified.includes(s.index));
  const combinedPublic = await combinePublicShares(ctx, publicShares);
  console.log(await isKeypair(ctx, secret, combinedPublic));
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
