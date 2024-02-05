import { Group, Point } from './backend/abstract';
import { SigmaProof } from './sigma';
import { Polynomial } from './polynomials';


export interface BaseShare<T> {
  value: T;
  index: number;
}


export abstract class BaseSharing<
  S,
  P extends Point,
  Q extends BaseShare<S>,
  R extends BaseShare<P>
> {
  ctx: Group<P>;
  nrShares: number;
  threshold: number;
  polynomial: Polynomial<P>;

  constructor(
    ctx: Group<P>, nrShares: number, threshold: number, polynomial: Polynomial<P>
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.nrShares = nrShares;
    this.polynomial = polynomial;
  }

  abstract getSecretShares: () => Promise<Q[]>;
  abstract getPublicShares: () => Promise<R[]>;

  getFeldmann = async (): Promise<{ commitments: P[] }> => {
    return this.polynomial.getFeldmann();
  }

  getPedersen = async (hPub?: P): Promise<{
    bindings: bigint[],
    hPub: P,
    commitments: P[],
  }> => {
    const { ctx, nrShares, polynomial } = this;
    return polynomial.getPedersen(nrShares, hPub || await ctx.randomPoint());
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
