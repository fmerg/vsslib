import { Dimension, Params } from './types';
import { CaseResult, CaseSpec, operationName } from './harness';


/** Only the dimensions an operation depends on, e.g. "n=5 t=3 sha256" */
export const formatParams = (uses: Dimension[], params: Params): string => {
  const parts = [];
  if (uses.includes('nrShares')) parts.push(`n=${params.nrShares}`);
  if (uses.includes('threshold')) parts.push(`t=${params.threshold}`);
  if (uses.includes('algorithm')) parts.push(params.algorithm);
  return parts.length > 0 ? parts.join(' ') : '-';
}


/** Duration given in ms, with a unit chosen to keep three significant digits */
export const formatDuration = (ms: number): string => {
  if (ms < 1e-3) return `${(ms * 1e6).toPrecision(3)} ns`;
  if (ms < 1) return `${(ms * 1e3).toPrecision(3)} µs`;
  if (ms < 1e3) return `${ms.toPrecision(3)} ms`;
  return `${(ms / 1e3).toPrecision(3)} s`;
}


const formatRate = (rate: number): string => rate >= 100 ?
  Math.round(rate).toLocaleString('en-US') :
  rate.toPrecision(3);


const median = (values: number[]): number => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}


/** Summary over the runs of a case; latencies in ms */
export type Summary = {
  /** Median over runs of the per-run median latency */
  median: number;
  /** Median over runs of the per-run median absolute deviation */
  mad: number;
  /** Median over runs of the per-run 99th percentile */
  p99: number;
  /** Spread of the per-run medians relative to their median, in percent;
   * undefined for a single run */
  range?: number;
  samples: number;
}


export const summarize = ({ runs }: CaseResult): Summary => {
  const medians = runs.map(run => run.median);
  const center = median(medians);
  return {
    median: center,
    mad: median(runs.map(run => run.mad)),
    p99: median(runs.map(run => run.p99)),
    range: runs.length > 1 ?
      (Math.max(...medians) - Math.min(...medians)) / center * 100 :
      undefined,
    samples: runs.reduce((total, run) => total + run.samples, 0),
  };
}


type Column = { header: string; width: number; align: 'left' | 'right' };

const COLUMNS: Column[] = [
  { header: 'operation', width: 40, align: 'left' },
  { header: 'system', width: 13, align: 'left' },
  { header: 'params', width: 20, align: 'left' },
  { header: 'median', width: 10, align: 'right' },
  { header: 'mad', width: 10, align: 'right' },
  { header: 'p99', width: 10, align: 'right' },
  { header: 'range', width: 7, align: 'right' },
  { header: 'ops/s', width: 10, align: 'right' },
  { header: 'samples', width: 8, align: 'right' },
];


const formatRow = (cells: string[]): string => cells.map((cell, i) => {
  const { width, align } = COLUMNS[i];
  return align === 'left' ? cell.padEnd(width) : cell.padStart(width);
}).join('  ').trimEnd();


/** Prints a fixed-width table row by row, so results show up as they come */
export class TableReporter {
  header = (): void => {
    console.log(formatRow(COLUMNS.map(c => c.header)));
    console.log(formatRow(COLUMNS.map(c => '-'.repeat(c.width))));
  }

  row = (result: CaseResult): void => {
    const { operation, uses, params } = result;
    const summary = summarize(result);
    console.log(formatRow([
      operation,
      params.system,
      formatParams(uses, params),
      formatDuration(summary.median),
      formatDuration(summary.mad),
      formatDuration(summary.p99),
      summary.range === undefined ? '-' : `${summary.range.toFixed(1)}%`,
      formatRate(1e3 / summary.median),
      String(summary.samples),
    ]));
  }
}


export const listCases = (plan: { spec: CaseSpec, uses: Dimension[] }[]): void => {
  for (const { spec, uses } of plan) {
    console.log(formatRow([
      operationName(spec), spec.params.system, formatParams(uses, spec.params),
    ]));
  }
}
