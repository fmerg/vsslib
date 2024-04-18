import { Polynomial } from './base';
import { Lagrange, XYTuple } from './core';
import { Point, Group } from '../../backend/abstract';

export {
  Polynomial,
  Lagrange,
}


export async function interpolate<P extends Point>(ctx: Group<P>, points: XYTuple[]): Promise<Lagrange<P>> {
    return new Lagrange(ctx, points.map(([x, y]) => [BigInt(x), BigInt(y)]));
}
