import { Group, Point } from './backend/abstract';
import { FieldPolynomial, randomPolynomial } from './lagrange';


export interface BaseShare<T> {
  value: T;
  index: number;
}


export abstract class BaseSharing<
  S, Q extends BaseShare<S>, P extends Point, R extends BaseShare<P>
> {
  ctx: Group<P>;
  nrShares: number;
  threshold: number;
  polynomial: FieldPolynomial<P>;

  constructor(
    ctx: Group<P>, nrShares: number, threshold: number, polynomial: FieldPolynomial<P>
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.nrShares = nrShares;
    this.polynomial = polynomial;
  }

  abstract getSecretShares: () => Promise<Q[]>;
  abstract getPublicShares: () => Promise<R[]>;
  abstract proveFeldmann: () => Promise<{ commitments: P[] }>;
  abstract provePedersen: (hPub: P) => Promise<{ bindings: bigint[], commitments: P[] }>;
}
