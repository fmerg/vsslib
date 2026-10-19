import os from 'node:os';
import { Command, InvalidArgumentError, Option } from 'commander';
import { Systems, Algorithms } from 'vsslib';
import type { System, Algorithm } from 'vsslib';
import { SUITES, MODULES } from './registry';
import { Params } from './types';
import { Planned, measure } from './harness';
import { TableReporter, listCases } from './report';


const SYSTEMS: string[] = Object.values(Systems);
const ALGORITHMS: string[] = [...new Set<string>(Object.values(Algorithms))];

const DEFAULT_SYSTEM = Systems.ED25519;
const DEFAULT_NR_SHARES = 5;
const DEFAULT_THRESHOLD = 3;


/** Comma-separated values without duplicates */
const parseList = (value: string): string[] => [
  ...new Set(value.split(',').map(v => v.trim()).filter(v => v.length > 0))
];


const parseChoices = (choices: string[], label: string, all?: string) => (value: string) => {
  const values = parseList(value);
  if (all !== undefined && values.includes(all)) return choices;
  for (const v of values) {
    if (!choices.includes(v)) throw new InvalidArgumentError(
      `Unsupported ${label}: ${v} (supported: ${choices.join(', ')})`
    );
  }
  return values;
}


const parsePositive = (value: string): number => {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) throw new InvalidArgumentError(
    `Not a positive integer: ${value}`
  );
  return parsed;
}


const parsePositives = (value: string): number[] => parseList(value).map(parsePositive);


/** Glob with * and ? wildcards, matched against the full or the bare operation name */
const globMatcher = (patterns: string[]) => {
  const regexes = patterns.map(pattern => new RegExp('^' + pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.') + '$'
  ));
  return (module: string, name: string) => regexes.some(
    regex => regex.test(`${module}/${name}`) || regex.test(name)
  );
}


type Options = {
  module?: string[];
  operation?: string[];
  system: string[];
  algorithm: string[];
  nrShares: number[];
  threshold: number[];
  time: number;
  iterations: number;
  warmup: number;
  list?: boolean;
  verbose?: boolean;
};


/** Cartesian product of the selected parameters, collapsing the dimensions an
 * operation does not depend on to their first value */
const expand = (opts: Options): Planned[] => {
  const matches = opts.operation ? globMatcher(opts.operation) : () => true;
  const plan: Planned[] = [];
  for (const { module, cases } of SUITES) {
    if (opts.module && !opts.module.includes(module)) continue;
    for (const bench of cases) {
      if (!matches(module, bench.name)) continue;
      const { uses } = bench;
      const algorithms = uses.includes('algorithm') ? opts.algorithm : opts.algorithm.slice(0, 1);
      const nrSharesList = uses.includes('nrShares') ? opts.nrShares : opts.nrShares.slice(0, 1);
      const thresholds = uses.includes('threshold') ? opts.threshold : opts.threshold.slice(0, 1);
      for (const system of opts.system) {
        for (const algorithm of algorithms) {
          for (let nrShares of nrSharesList) {
            for (let threshold of thresholds) {
              if (threshold > nrShares) {
                if (uses.includes('nrShares') && uses.includes('threshold')) continue;
                // Inputs of the operation may still require t <= n
                if (uses.includes('threshold')) nrShares = threshold;
                else threshold = nrShares;
              }
              const params: Params = {
                system: system as System,
                algorithm: algorithm as Algorithm,
                nrShares,
                threshold,
              };
              plan.push({ module, bench, params });
            }
          }
        }
      }
    }
  }
  return plan;
}


const printEnvironment = (opts: Options, plan: Planned[]): void => {
  const cpus = os.cpus();
  console.error(`node ${process.version} on ${cpus[0]?.model ?? 'unknown cpu'} (${cpus.length} cores)`);
  console.error(`systems: ${opts.system.join(', ')}`);
  console.error(`algorithms: ${opts.algorithm.join(', ')}`);
  console.error(`nr shares: ${opts.nrShares.join(', ')}; thresholds: ${opts.threshold.join(', ')}`);
  console.error(`time: ${opts.time} ms, iterations: ${opts.iterations}, warmup: ${opts.warmup} ms`);
  console.error(`${plan.length} cases\n`);
}


async function main(opts: Options): Promise<void> {
  const plan = expand(opts);
  if (plan.length === 0) {
    console.error('No benchmark matches the given options');
    process.exit(1);
  }
  if (opts.list) {
    listCases(plan);
    return;
  }
  if (opts.verbose) printEnvironment(opts, plan);
  const timing = { time: opts.time, iterations: opts.iterations, warmupTime: opts.warmup };
  const reporter = new TableReporter();
  reporter.header();
  for (const planned of plan) {
    reporter.row(await measure(planned, timing));
  }
}


const program = new Command()
  .name('./bench.sh')
  .description(
    'Benchmark the high-level operations of vsslib. List-valued options take\n' +
    'comma-separated values, and every combination of them is measured;\n' +
    'parameters that an operation does not depend on are not repeated.'
  )
  .option('-m, --module <LIST>', `modules: ${MODULES.join(', ')} (default: all)`,
    parseChoices(MODULES, 'module'))
  .option('-o, --operation <PATTERNS>',
    'operations to run, by name or glob, e.g. "add*" or "secrets/random*"', parseList)
  .addOption(new Option('-s, --system <LIST>', 'systems, or "all"')
    .argParser(parseChoices(SYSTEMS, 'system', 'all'))
    .default([DEFAULT_SYSTEM], DEFAULT_SYSTEM))
  .addOption(new Option('-a, --algorithm <LIST>', 'hash algorithms')
    .argParser(parseChoices(ALGORITHMS, 'algorithm'))
    .default([Algorithms.DEFAULT], Algorithms.DEFAULT))
  .addOption(new Option('-n, --nr-shares <LIST>', 'numbers of shares')
    .argParser(parsePositives)
    .default([DEFAULT_NR_SHARES], String(DEFAULT_NR_SHARES)))
  .addOption(new Option('-t, --threshold <LIST>', 'thresholds')
    .argParser(parsePositives)
    .default([DEFAULT_THRESHOLD], String(DEFAULT_THRESHOLD)))
  .option('--time <MS>', 'minimum measuring time per case', parsePositive, 500)
  .option('--iterations <NR>', 'minimum number of samples per case', parsePositive, 10)
  .option('--warmup <MS>', 'warm-up time per case', parsePositive, 100)
  .option('-l, --list', 'list the selected cases without running them')
  .option('-v, --verbose', 'print the environment and the run configuration')
  .addHelpText('after', [
    '',
    'Systems:',
    `  ${SYSTEMS.join(', ')}`,
    '',
    'Hash algorithms:',
    `  ${ALGORITHMS.join(', ')}`,
    '',
    'Examples:',
    '  ./bench.sh -m secrets -s ed25519,p256',
    '  ./bench.sh -o "add*" -n 5,20,100 -s all',
  ].join('\n'))
  .action(main);


program.parseAsync().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
