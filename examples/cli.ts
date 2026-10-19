/** Command-line handling shared by the examples; not part of the flows */
import { parseArgs, ParseArgsOptionsConfig } from 'node:util';
import { initBackend, Systems } from 'vsslib';
import type { System } from 'vsslib';


const COMMON_OPTIONS = {
  system: { type: 'string', short: 's', default: 'ed25519' },
  'nr-shares': { type: 'string', short: 'n', default: '5' },
  threshold: { type: 'string', short: 't', default: '3' },
  help: { type: 'boolean', short: 'h' },
} as const;

const COMMON_USAGE = `
  -s, --system <SYSTEM>       ${Object.values(Systems).join(', ')} (default: ed25519)
  -n, --nr-shares <N>         number of shareholders (default: 5)
  -t, --threshold <T>         threshold (default: 3)
  -h, --help                  display this help and exit`;


const parseInteger = (name: string, value: string): number => {
  if (!/^\d+$/.test(value)) throw new Error(`--${name} must be a positive integer`);
  return parseInt(value);
}


/** Parses the common options plus `extra`, printing `usage` on --help */
export const parseOptions = (usage: string, extra: ParseArgsOptionsConfig) => {
  const { values } = parseArgs({ options: { ...COMMON_OPTIONS, ...extra } }) as {
    values: Record<string, string | boolean | undefined>
  };
  if (values.help) {
    console.log(usage.trim() + COMMON_USAGE);
    process.exit(0);
  }
  const system = values.system as System;
  if (!Object.values(Systems).includes(system)) throw new Error(`Unsupported system: ${system}`);
  return {
    ctx: initBackend(system),
    nrShares: parseInteger('nr-shares', values['nr-shares'] as string),
    threshold: parseInteger('threshold', values.threshold as string),
    values,
  };
}


/** Comma-separated share indexes, e.g. "1,3,4" */
export const parseIndexes = (value: string): number[] =>
  value.split(',').map(index => parseInteger('combine', index));


/** Runs `main` when the file is executed rather than imported */
export const runMain = (module: NodeJS.Module, main: () => Promise<void>) => {
  if (require.main !== module) return;
  main().catch(err => {
    console.error(`error: ${err.message}`);
    process.exit(1);
  });
}
