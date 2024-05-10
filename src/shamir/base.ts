import { Group, Point } from '../backend/abstract';
import { FieldPolynomial } from '../lagrange';


export interface BaseShare<V> {
  value: V;
  index: number;
}


export interface SecretShare<
  P extends Point,
  V,
  C,
  B,
> extends BaseShare<V>{
  ctx: Group<P>;
  verifyFeldmann: (commitments: C[]) => Promise<boolean>;
  verifyPedersen: (binding: B, commitments: C[], h: C) => Promise<boolean>;
}


export interface PubShare<
  P extends Point,
  V,
> extends BaseShare<V> {
}


export abstract class BaseSharing<
  P extends Point,
  C,
  B,
  S,
  R,
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

  abstract getSecretShares: () => Promise<S[]>;
  abstract getPublicShares: () => Promise<R[]>;
  abstract proveFeldmann: () => Promise<{ commitments: C[] }>;
  abstract provePedersen: (h: C) => Promise<{ commitments: C[], bindings: B[] }>;
}
