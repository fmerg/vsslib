import { Dimension, Params } from './types';
import { Planned, Result, operationName } from './harness';


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


type Column = { header: string; width: number; align: 'left' | 'right' };

const COLUMNS: Column[] = [
  { header: 'operation', width: 40, align: 'left' },
  { header: 'system', width: 13, align: 'left' },
  { header: 'params', width: 20, align: 'left' },
  { header: 'mean', width: 10, align: 'right' },
  { header: 'p99', width: 10, align: 'right' },
  { header: '±rme', width: 8, align: 'right' },
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

  row = (result: Result): void => {
    const { operation, uses, params } = result;
    console.log(formatRow([
      operation,
      params.system,
      formatParams(uses, params),
      formatDuration(result.mean),
      formatDuration(result.p99),
      `${result.rme.toFixed(2)}%`,
      formatRate(result.throughput),
      String(result.samples),
    ]));
  }
}


export const listCases = (plan: Planned[]): void => {
  for (const planned of plan) {
    const { bench: { uses }, params } = planned;
    console.log(formatRow([
      operationName(planned), params.system, formatParams(uses, params),
    ]));
  }
}
