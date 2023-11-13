import { Group, Point } from './backend/abstract';
import { SigmaProof } from './sigma';
import { Polynomial } from './polynomials';


export interface BaseShare<T> {
  value: T;
  index: number;
}


export abstract class BaseDistribution<
  S,
  P extends Point,
  Q extends BaseShare<S>,
  R extends BaseShare<P>
> {
  ctx: Group<P>;
  nrShares: number;
  threshold: number;
  polynomial: Polynomial<P>;

  constructor(ctx: Group<P>, nrShares: number, threshold: number, polynomial: Polynomial<P>) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.nrShares = nrShares;
    this.polynomial = polynomial;
  }

  abstract getSecretShares: () => Promise<Q[]>;
  abstract getPublicShares: () => Promise<R[]>;

  getFeldmannCommitments = async (): Promise<{ commitments: P[] }> => {
    return this.polynomial.generateFeldmannCommitments();
  }

  getPedersenCommitments = async (hPub?: P): Promise<{
    bindings: bigint[],
    hPub: P,
    commitments: P[],
  }> => {
    const { ctx, nrShares, polynomial } = this;
    return polynomial.generatePedersenCommitments(nrShares, hPub || await ctx.randomPoint());
  }
}


export class PartialDecryptor<P extends Point> implements BaseShare<P> {
  value: P;
  index: number;
  proof: SigmaProof<P>;

  constructor(value: P, index: number, proof: SigmaProof<P>) {
    this.value = value;
    this.index = index;
    this.proof = proof;
  }
};
