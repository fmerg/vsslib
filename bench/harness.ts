import { Bench } from 'tinybench';
import { initBackend } from 'vsslib';
import { BenchCase, Dimension, Params } from './types';


export type Timing = {
  /** Minimum measuring time in ms */
  time: number;
  /** Minimum number of samples */
  iterations: number;
  /** Warm-up time in ms */
  warmupTime: number;
};

/** A benchmark case bound to concrete parameters */
export type Planned = {
  module: string;
  bench: BenchCase<unknown>;
  params: Params;
};

export type Result = {
  operation: string;
  uses: Dimension[];
  params: Params;
  /** Latency statistics in ms */
  mean: number;
  p50: number;
  p99: number;
  /** Relative margin of error of the mean latency, in percent */
  rme: number;
  samples: number;
  /** Mean throughput in operations per second */
  throughput: number;
};


export const operationName = ({ module, bench }: Planned) => `${module}/${bench.name}`;


export async function measure(planned: Planned, timing: Timing): Promise<Result> {
  const { bench: { uses, setup, run }, params } = planned;
  const operation = operationName(planned);
  const ctx = initBackend(params.system);
  const state = await setup(ctx, params);
  const bench = new Bench({
    time: timing.time,
    iterations: timing.iterations,
    warmupTime: timing.warmupTime,
    warmupIterations: 1,
    throws: true,
  });
  bench.add(operation, async () => { await run(ctx, state, params); });
  await bench.run();
  const result = bench.tasks[0].result;
  if (result.state !== 'completed') throw new Error(
    `Benchmark ${operation} did not complete: ${result.state}`
  );
  const { latency, throughput } = result;
  return {
    operation,
    uses,
    params,
    mean: latency.mean,
    p50: latency.p50,
    p99: latency.p99,
    rme: latency.rme,
    samples: latency.samplesCount,
    throughput: throughput.mean,
  };
}
