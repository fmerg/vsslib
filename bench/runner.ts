import path from 'node:path';
import { spawn } from 'node:child_process';
import { CaseSpec, RunResult, Timing, operationName } from './harness';


const ROOT = path.resolve(__dirname, '..');
const TSX = path.join(ROOT, 'node_modules', '.bin', 'tsx');
const WORKER = path.join(__dirname, 'worker.ts');


/** Runs a case in a fresh process, optionally pinned to the given CPUs */
export const runInWorker = (
  spec: CaseSpec, timing: Timing, cpus?: string
): Promise<RunResult> => new Promise((resolve, reject) => {
  const args = ['--tsconfig', path.join(ROOT, 'tsconfig.json'), WORKER, JSON.stringify({ spec, timing })];
  const child = cpus ?
    spawn('taskset', ['--cpu-list', cpus, TSX, ...args], { stdio: ['ignore', 'pipe', 'inherit'] }) :
    spawn(TSX, args, { stdio: ['ignore', 'pipe', 'inherit'] });
  let output = '';
  child.stdout.on('data', (chunk: Buffer) => { output += chunk; });
  child.on('error', reject);
  child.on('close', (code) => {
    if (code !== 0) return reject(new Error(
      `Benchmark ${operationName(spec)} on ${spec.params.system} failed with exit code ${code}`
    ));
    resolve(JSON.parse(output));
  });
});
