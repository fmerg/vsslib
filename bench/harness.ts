import { Bench } from 'tinybench';
import { initBackend } from 'vsslib';
import { SUITES } from './registry';
import { BenchCase, Dimension, Params } from './types';


export type Timing = {
  /** Minimum measuring time in ms */
  time: number;
  /** Minimum number of samples */
  iterations: number;
  /** Warm-up time in ms */
  warmupTime: number;
  /** Number of distinct inputs cycled through by the timed operation */
  poolSize: number;
};

/** Serializable identification of a benchmark case bound to parameters */
export type CaseSpec = {
  module: string;
  name: string;
  params: Params;
};

/** Statistics of a single run, i.e. one process; latencies in ms */
export type RunResult = {
  median: number;
  mad: number;
  mean: number;
  p99: number;
  samples: number;
};

export type CaseResult = {
  operation: string;
  uses: Dimension[];
  params: Params;
  runs: RunResult[];
};


export const operationName = ({ module, name }: CaseSpec) => `${module}/${name}`;


export const findCase = ({ module, name }: CaseSpec): BenchCase<unknown> => {
  const bench = SUITES.find(suite => suite.module === module)?.cases.find(c => c.name === name);
  if (!bench) throw new Error(`Unknown benchmark: ${module}/${name}`);
  return bench;
}


/** Measures a case in the current process; meant to run in a fresh worker
 * process, so that cases cannot affect each other through JIT or heap state */
export async function measure(spec: CaseSpec, timing: Timing): Promise<RunResult> {
  const { setup, run } = findCase(spec);
  const { params } = spec;
  const ctx = initBackend(params.system);
  // Distinct inputs, since the arithmetic is not constant-time
  const pool: unknown[] = [];
  for (let i = 0; i < timing.poolSize; i++) pool.push(await setup(ctx, params));
  let next = 0;
  const bench = new Bench({
    time: timing.time,
    iterations: timing.iterations,
    warmupTime: timing.warmupTime,
    warmupIterations: 1,
    throws: true,
  });
  bench.add(operationName(spec), async () => {
    await run(ctx, pool[next], params);
    next = (next + 1) % pool.length;
  });
  await bench.run();
  const result = bench.tasks[0].result;
  if (result.state !== 'completed') throw new Error(
    `Benchmark ${operationName(spec)} did not complete: ${result.state}`
  );
  const { latency } = result;
  return {
    median: latency.p50,
    mad: latency.mad,
    mean: latency.mean,
    p99: latency.p99,
    samples: latency.samplesCount,
  };
}
