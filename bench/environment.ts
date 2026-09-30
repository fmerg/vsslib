import os from 'node:os';
import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { RUNNER } from './runner';


export type Environment = {
  node: string;
  /** How the workers run; absent in baselines taken through tsx */
  runner?: string;
  cpu: string;
  cores: number;
  /** Distinct frequency governors over all CPUs; empty where unavailable */
  governors: string[];
  /** Whether the CPUs differ in maximum frequency, e.g. performance and efficiency cores */
  hybrid: boolean;
  /** CPU list the workers are pinned to, if any */
  cpus?: string;
  commit?: string;
  dirty?: boolean;
};


/** Distinct values of a cpufreq attribute over all CPUs */
const readCpufreq = (attribute: string): string[] => {
  const values = new Set<string>();
  for (const cpu of os.cpus().keys()) {
    try {
      values.add(fs.readFileSync(
        `/sys/devices/system/cpu/cpu${cpu}/cpufreq/${attribute}`, 'utf8'
      ).trim());
    } catch {
      // Not exposed on this platform
    }
  }
  return [...values];
}


const git = (args: string[]): string | undefined => {
  try {
    return execFileSync('git', args, { cwd: __dirname, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return undefined;
  }
}


export const collectEnvironment = (cpus?: string): Environment => {
  const status = git(['status', '--porcelain']);
  return {
    node: process.version,
    runner: RUNNER,
    cpu: os.cpus()[0]?.model ?? 'unknown',
    cores: os.cpus().length,
    governors: readCpufreq('scaling_governor'),
    hybrid: readCpufreq('cpuinfo_max_freq').length > 1,
    cpus,
    commit: git(['rev-parse', '--short', 'HEAD']),
    dirty: status === undefined ? undefined : status.length > 0,
  };
}


/** Conditions known to distort measurements */
export const environmentWarnings = (env: Environment): string[] => {
  const warnings = [];
  const others = env.governors.filter(governor => governor !== 'performance');
  if (others.length > 0) warnings.push(
    `CPU frequency governor is ${others.join(', ')}, not performance; results may vary with frequency scaling`
  );
  if (env.hybrid && env.cpus === undefined) warnings.push(
    'CPUs differ in maximum frequency and workers are not pinned (see --cpus); they may migrate between core types'
  );
  return warnings;
}


export const assertTaskset = (): void => {
  try {
    execFileSync('taskset', ['--version'], { stdio: 'ignore' });
  } catch {
    throw new Error('--cpus requires taskset (util-linux), which is not available');
  }
}
