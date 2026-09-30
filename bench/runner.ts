import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { buildSync } from 'esbuild';
import { CaseSpec, RunResult, Timing, operationName } from './harness';


const ROOT = path.resolve(__dirname, '..');
// Inside node_modules, so that the bundle resolves the packages left out of it
const CACHE = path.join(ROOT, 'node_modules', '.cache', 'vsslib-bench');

/** How the workers run, recorded with the results; baselines without it were
 * taken by running the worker through tsx */
export const RUNNER = 'node, esbuild bundle';


/** Bundles the worker with the library sources for plain node and returns the
 * path of the bundle, which is removed on exit. The workers do not run through
 * tsx, since tsx transforms the ESM-only noble packages to CommonJS, which
 * makes their hashes up to 35 times slower; packages are left out of the
 * bundle, so that node loads them natively as it does for users of dist */
export const bundleWorker = (): string => {
  fs.mkdirSync(CACHE, { recursive: true });
  const dir = fs.mkdtempSync(path.join(CACHE, 'run-'));
  process.on('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  const outfile = path.join(dir, 'worker.cjs');
  buildSync({
    entryPoints: [path.join(__dirname, 'worker.ts')],
    tsconfig: path.join(__dirname, 'tsconfig.json'),
    bundle: true,
    platform: 'node',
    format: 'cjs',
    // As dist
    target: 'es2020',
    packages: 'external',
    outfile,
    logLevel: 'warning',
  });
  return outfile;
}


/** Runs a case in a fresh process, optionally pinned to the given CPUs */
export const runInWorker = (
  worker: string, spec: CaseSpec, timing: Timing, cpus?: string
): Promise<RunResult> => new Promise((resolve, reject) => {
  const args = [worker, JSON.stringify({ spec, timing })];
  // taskset replaces itself with node, so that signals reach the worker directly
  const child = cpus ?
    spawn('taskset', ['--cpu-list', cpus, process.execPath, ...args], { stdio: ['ignore', 'pipe', 'inherit'] }) :
    spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'inherit'] });
  let output = '';
  child.stdout.on('data', (chunk: Buffer) => { output += chunk; });
  child.on('error', reject);
  child.on('close', (code, signal) => {
    const label = `Benchmark ${operationName(spec)} on ${spec.params.system}`;
    if (code !== 0) return reject(new Error(signal ?
      `${label} was killed by ${signal}` :
      `${label} failed with exit code ${code}`
    ));
    try {
      resolve(JSON.parse(output));
    } catch {
      reject(new Error(`${label} produced invalid output: ${output.slice(0, 200)}`));
    }
  });
});
