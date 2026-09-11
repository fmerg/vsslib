import fs from 'node:fs';
import path from 'node:path';
import { CaseResult, RunResult, Timing } from './harness';
import { Environment } from './environment';
import { Summary, formatParams, summarize } from './report';
import { Dimension, Params } from './types';


export const BASELINES_DIR = path.join(__dirname, 'baselines');

const DOCUMENT_VERSION = 1;


export type Settings = Timing & { runs: number };

export type Entry = {
  operation: string;
  uses: Dimension[];
  params: Params;
  summary: Summary;
  runs: RunResult[];
};

/** Results of a whole invocation, as saved to a baseline or printed as JSON */
export type Document = {
  version: number;
  createdAt: string;
  environment: Environment;
  settings: Settings;
  results: Entry[];
};


/** Identifies a case across invocations; dimensions that the operation does
 * not depend on are left out, as they do not affect the measurement */
export const caseKey = ({ operation, uses, params }: Omit<CaseResult, 'runs'>): string =>
  `${operation} ${params.system} ${formatParams(uses, params)}`;


export const toDocument = (
  results: CaseResult[], environment: Environment, settings: Settings
): Document => ({
  version: DOCUMENT_VERSION,
  createdAt: new Date().toISOString(),
  environment,
  settings,
  results: results.map(result => ({ ...result, summary: summarize(result) })),
});


export const validateBaselineName = (name: string): string => {
  if (!/^[\w.-]+$/.test(name)) throw new Error(
    `Invalid baseline name: ${name} (letters, digits, '.', '_' and '-' only)`
  );
  return name;
}


const baselinePath = (name: string): string => path.join(BASELINES_DIR, `${name}.json`);


export const saveBaseline = (name: string, document: Document): string => {
  fs.mkdirSync(BASELINES_DIR, { recursive: true });
  const file = baselinePath(name);
  fs.writeFileSync(file, JSON.stringify(document, null, 2) + '\n');
  return file;
}


export const loadBaseline = (name: string): Document => {
  const file = baselinePath(name);
  if (!fs.existsSync(file)) {
    const available = fs.existsSync(BASELINES_DIR) ?
      fs.readdirSync(BASELINES_DIR).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5)) :
      [];
    throw new Error(
      `No baseline named ${name} (available: ${available.join(', ') || 'none'})`
    );
  }
  const document: Document = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (document.version !== DOCUMENT_VERSION) throw new Error(
    `Baseline ${name} has version ${document.version}, expected ${DOCUMENT_VERSION}`
  );
  return document;
}


export type Verdict = 'slower' | 'faster' | 'unchanged' | 'new';

export type Comparison = {
  verdict: Verdict;
  /** Median latency of the baseline in ms */
  baseline?: number;
  /** Change of the median latency relative to the baseline, in percent */
  change?: number;
};


/** Probability that the run medians of two invocations of unchanged code
 * separate completely by chance, with r and s runs: 2 / C(r + s, r) */
export const separationChance = (r: number, s: number): number => {
  let combinations = 1;
  for (let i = 1; i <= r; i++) combinations = combinations * (s + i) / i;
  return 2 / combinations;
}


/** A case changed if its median moved by more than the tolerance and the run
 * medians of the two invocations do not overlap; see separationChance for the
 * probability of a false verdict, e.g. 10% for 3 runs per side and below 1%
 * for 5 */
export const compareResult = (
  result: CaseResult, baseline: Map<string, Entry>, tolerance: number
): Comparison => {
  const entry = baseline.get(caseKey(result));
  if (!entry) return { verdict: 'new' };
  const current = result.runs.map(run => run.median);
  const previous = entry.runs.map(run => run.median);
  const base = entry.summary.median;
  const change = (summarize(result).median - base) / base * 100;
  const separated = Math.max(...current) < Math.min(...previous) ||
    Math.min(...current) > Math.max(...previous);
  const verdict = Math.abs(change) > tolerance && separated ?
    (change > 0 ? 'slower' : 'faster') :
    'unchanged';
  return { verdict, baseline: base, change };
}


export const indexBaseline = (document: Document): Map<string, Entry> =>
  new Map(document.results.map(entry => [caseKey(entry), entry]));


/** Differences between the conditions of a baseline and of the current
 * invocation that make a comparison less meaningful */
export const comparabilityWarnings = (
  document: Document, environment: Environment, settings: Settings
): string[] => {
  const warnings = [];
  const previous = document.environment;
  const fields: [string, unknown, unknown][] = [
    ['node', previous.node, environment.node],
    ['cpu', previous.cpu, environment.cpu],
    ['governors', previous.governors.join(','), environment.governors.join(',')],
    ['pinned cpus', previous.cpus ?? 'none', environment.cpus ?? 'none'],
    ...Object.keys(settings).map(key => [
      key, document.settings[key as keyof Settings], settings[key as keyof Settings],
    ] as [string, unknown, unknown]),
  ];
  for (const [field, before, now] of fields) {
    if (before !== now) warnings.push(`baseline differs in ${field}: ${before} vs ${now}`);
  }
  if (document.settings.runs !== settings.runs) warnings.push(
    'with these run counts, unchanged cases separate by chance with probability ' +
    `${(separationChance(document.settings.runs, settings.runs) * 100).toFixed(1)}%`
  );
  if (previous.dirty) warnings.push(
    `baseline was taken on a dirty tree (${previous.commit ?? 'unknown commit'})`
  );
  return warnings;
}
