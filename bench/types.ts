import { initBackend } from 'vsslib';
import type { System, Algorithm } from 'vsslib';


export type Ctx = ReturnType<typeof initBackend>;

export type Params = {
  system: System;
  algorithm: Algorithm;
  nrShares: number;
  threshold: number;
};

/** Parameters besides the system that may affect the cost of an operation */
export type Dimension = 'algorithm' | 'nrShares' | 'threshold';

export type BenchCase<S = unknown> = {
  name: string;
  /** Dimensions the operation depends on; the sweep collapses the others */
  uses: Dimension[];
  /** Prepares the inputs of the operation; not timed */
  setup: (ctx: Ctx, params: Params) => Promise<S>;
  /** The timed operation */
  run: (ctx: Ctx, state: S, params: Params) => Promise<unknown>;
};

export type Suite = {
  module: string;
  cases: BenchCase<any>[];  // eslint-disable-line @typescript-eslint/no-explicit-any
};

/** Preserves the state type across setup and run of a single case */
export const defineCase = <S>(c: BenchCase<S>): BenchCase<S> => c;
