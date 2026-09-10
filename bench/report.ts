import { Dimension, Params } from './types';
import { CaseResult, CaseSpec, operationName } from './harness';
import type { Comparison } from './baseline';


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


const formatChange = (change: number): string =>
  `${change > 0 ? '+' : ''}${change.toFixed(1)}%`;


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


export const summarize = ({ runs }: Pick<CaseResult, 'runs'>): Summary => {
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


export const FORMATS = ['table', 'markdown', 'csv', 'json'] as const;
export type Format = typeof FORMATS[number];

/** Formats that render one line per case, so that results show up as they come */
export type LineFormat = Exclude<Format, 'json'>;


type Column = {
  header: string;
  width: number;
  align: 'left' | 'right';
  cell: (result: CaseResult, summary: Summary, comparison?: Comparison) => string;
};

const COLUMNS: Column[] = [
  { header: 'operation', width: 40, align: 'left', cell: r => r.operation },
  { header: 'system', width: 13, align: 'left', cell: r => r.params.system },
  { header: 'params', width: 20, align: 'left', cell: r => formatParams(r.uses, r.params) },
  { header: 'median', width: 10, align: 'right', cell: (_, s) => formatDuration(s.median) },
  { header: 'mad', width: 10, align: 'right', cell: (_, s) => formatDuration(s.mad) },
  { header: 'p99', width: 10, align: 'right', cell: (_, s) => formatDuration(s.p99) },
  {
    header: 'range', width: 7, align: 'right',
    cell: (_, s) => s.range === undefined ? '-' : `${s.range.toFixed(1)}%`,
  },
  { header: 'ops/s', width: 10, align: 'right', cell: (_, s) => formatRate(1e3 / s.median) },
  { header: 'samples', width: 8, align: 'right', cell: (_, s) => String(s.samples) },
];

const COMPARISON_COLUMNS: Column[] = [
  {
    header: 'baseline', width: 10, align: 'right',
    cell: (_, __, c) => c?.baseline === undefined ? '-' : formatDuration(c.baseline),
  },
  {
    header: 'change', width: 8, align: 'right',
    cell: (_, __, c) => c?.change === undefined ? '-' : formatChange(c.change),
  },
  { header: 'verdict', width: 9, align: 'left', cell: (_, __, c) => c?.verdict ?? '-' },
];


/** Raw values for further processing; latencies in ms, unused dimensions empty */
const CSV_HEADERS = [
  'operation', 'system', 'algorithm', 'nrShares', 'threshold', 'median_ms', 'mad_ms',
  'p99_ms', 'range_pct', 'ops_per_s', 'samples', 'runs',
];

const CSV_COMPARISON_HEADERS = ['baseline_median_ms', 'change_pct', 'verdict'];

/** Six significant digits, beyond the precision of any measurement here */
const csvNumber = (value: number): string => String(Number(value.toPrecision(6)));

const csvRow = (result: CaseResult, summary: Summary, comparison?: Comparison): string[] => {
  const { operation, uses, params } = result;
  const row = [
    operation,
    params.system,
    uses.includes('algorithm') ? params.algorithm : '',
    uses.includes('nrShares') ? String(params.nrShares) : '',
    uses.includes('threshold') ? String(params.threshold) : '',
    csvNumber(summary.median),
    csvNumber(summary.mad),
    csvNumber(summary.p99),
    summary.range === undefined ? '' : csvNumber(summary.range),
    csvNumber(1e3 / summary.median),
    String(summary.samples),
    String(result.runs.length),
  ];
  if (comparison) row.push(
    comparison.baseline === undefined ? '' : csvNumber(comparison.baseline),
    comparison.change === undefined ? '' : csvNumber(comparison.change),
    comparison.verdict,
  );
  return row;
}


export class LineFormatter {
  format: LineFormat;
  columns: Column[];
  withComparison: boolean;

  constructor(format: LineFormat, withComparison: boolean) {
    this.format = format;
    this.withComparison = withComparison;
    this.columns = withComparison ? [...COLUMNS, ...COMPARISON_COLUMNS] : COLUMNS;
  }

  header = (): string[] => {
    switch (this.format) {
      case 'table':
        return [
          this.table(this.columns.map(c => c.header)),
          this.table(this.columns.map(c => '-'.repeat(c.width))),
        ];
      case 'markdown':
        return [
          `| ${this.columns.map(c => c.header).join(' | ')} |`,
          `|${this.columns.map(c => c.align === 'left' ? ' --- ' : ' ---: ').join('|')}|`,
        ];
      case 'csv':
        return [[...CSV_HEADERS, ...(this.withComparison ? CSV_COMPARISON_HEADERS : [])].join(',')];
    }
  }

  row = (result: CaseResult, comparison?: Comparison): string => {
    const summary = summarize(result);
    const cells = this.columns.map(c => c.cell(result, summary, comparison));
    switch (this.format) {
      case 'table':
        return this.table(cells);
      case 'markdown':
        return `| ${cells.join(' | ')} |`;
      case 'csv':
        return csvRow(result, summary, comparison).join(',');
    }
  }

  private table = (cells: string[]): string => cells.map((cell, i) => {
    const { width, align } = this.columns[i];
    return align === 'left' ? cell.padEnd(width) : cell.padStart(width);
  }).join('  ').trimEnd();
}


export const listCases = (plan: { spec: CaseSpec, uses: Dimension[] }[]): void => {
  const formatter = new LineFormatter('table', false);
  for (const { spec, uses } of plan) {
    const cells = [operationName(spec), spec.params.system, formatParams(uses, spec.params)];
    console.log(cells.map((cell, i) => cell.padEnd(formatter.columns[i].width)).join('  ').trimEnd());
  }
}
