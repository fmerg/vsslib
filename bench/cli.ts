import { Command, InvalidArgumentError, Option } from 'commander';
import { Systems, Algorithms } from 'vsslib';
import type { System, Algorithm } from 'vsslib';
import { SUITES, MODULES } from './registry';
import { Dimension, Params } from './types';
import { CaseResult, CaseSpec, Timing } from './harness';
import { runInWorker } from './runner';
import { assertTaskset, collectEnvironment, environmentWarnings } from './environment';
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


const parseCpus = (value: string): string => {
  if (!/^\d+(-\d+)?(,\d+(-\d+)?)*$/.test(value)) throw new InvalidArgumentError(
    `Not a CPU list: ${value} (e.g. 0-7 or 0,2,4)`
  );
  return value;
}


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
  runs: number;
  pool: number;
  cpus?: string;
  list?: boolean;
  verbose?: boolean;
};


/** Cartesian product of the selected parameters, collapsing the dimensions an
 * operation does not depend on to their first value */
type Planned = { spec: CaseSpec, uses: Dimension[] };

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
              plan.push({ spec: { module, name: bench.name, params }, uses });
            }
          }
        }
      }
    }
  }
  return plan;
}


const printConfiguration = (opts: Options, plan: Planned[]): void => {
  const env = collectEnvironment(opts.cpus);
  console.error(`node ${env.node} on ${env.cpu} (${env.cores} cpus)`);
  console.error(`governors: ${env.governors.join(', ') || 'unknown'}; pinned to: ${env.cpus ?? 'none'}`);
  console.error(`commit: ${env.commit ?? 'unknown'}${env.dirty ? ' (dirty)' : ''}`);
  console.error(`systems: ${opts.system.join(', ')}`);
  console.error(`algorithms: ${opts.algorithm.join(', ')}`);
  console.error(`nr shares: ${opts.nrShares.join(', ')}; thresholds: ${opts.threshold.join(', ')}`);
  console.error(`time: ${opts.time} ms, iterations: ${opts.iterations}, warmup: ${opts.warmup} ms`);
  console.error(`runs: ${opts.runs}, input pool: ${opts.pool}`);
  console.error(`${plan.length} cases\n`);
}


const progress = (message: string): void => {
  if (process.stderr.isTTY) process.stderr.write(`\r\x1b[K${message}`);
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
  if (opts.cpus) assertTaskset();
  for (const warning of environmentWarnings(collectEnvironment(opts.cpus))) {
    console.error(`warning: ${warning}`);
  }
  if (opts.verbose) printConfiguration(opts, plan);
  const timing: Timing = {
    time: opts.time,
    iterations: opts.iterations,
    warmupTime: opts.warmup,
    poolSize: opts.pool,
  };
  const results: CaseResult[] = plan.map(({ spec, uses }) => ({
    operation: `${spec.module}/${spec.name}`, uses, params: spec.params, runs: [],
  }));
  const reporter = new TableReporter();
  // Runs go round-robin over the cases, so that slow drifts of the machine
  // (e.g. thermal) spread over all cases instead of biasing some of them;
  // rows are printed as cases complete their last run
  for (let round = 1; round <= opts.runs; round++) {
    if (round === opts.runs) {
      progress('');
      reporter.header();
    }
    for (const [i, { spec }] of plan.entries()) {
      if (round < opts.runs) progress(`run ${round}/${opts.runs}: ${i + 1}/${plan.length}`);
      results[i].runs.push(await runInWorker(spec, timing, opts.cpus));
      if (round === opts.runs) reporter.row(results[i]);
    }
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
  .option('--time <MS>', 'minimum measuring time per run', parsePositive, 500)
  .option('--iterations <NR>', 'minimum number of samples per run', parsePositive, 10)
  .option('--warmup <MS>', 'warm-up time per run', parsePositive, 250)
  .option('-r, --runs <NR>', 'independent runs per case, each in a fresh process', parsePositive, 3)
  .option('--pool <NR>', 'distinct inputs cycled through by each case', parsePositive, 32)
  .option('--cpus <LIST>', 'pin the runs to these CPUs with taskset, e.g. 0-7', parseCpus)
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
    '  ./bench.sh -m secrets --cpus 0-7 -r 5',
    '',
    'Columns: median latency, median absolute deviation and 99th percentile',
    '(each the median over runs), spread of the run medians relative to the',
    'median (range), throughput derived from the median, and total samples.',
  ].join('\n'))
  .action(main);


program.parseAsync().catch((err: unknown) => {
  // Worker failures have already printed their own stack trace
  console.error(`error: ${err instanceof Error ? err.message : err}`);
  process.exit(1);
});
