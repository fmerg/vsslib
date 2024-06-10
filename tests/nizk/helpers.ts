import { Algorithm } from '../../src/types';
import { Point, Group } from '../../src/backend/abstract';
import { leInt2Buff, leBuff2Int } from '../../src/arith';
import { DlogPair, DDHTuple, GenericLinear } from '../../src/nizk';
import { hash } from '../../src/crypto';


const __0n = BigInt(0);
const __1n = BigInt(1);


/** Create generic linear relation with given dimensions */
export async function createGenericLinear<P extends Point>(
  ctx: Group<P>,
  opts: { m: number, n: number },
): Promise<[bigint[], GenericLinear<P>]>{
  const { randomScalar, randomPoint, neutral, exp, operate } = ctx;
  const { m, n } = opts;
  const witness = new Array(n);
  const vs = Array.from({ length: m }, (_, i) => neutral);
  const us = Array.from({ length: m }, (_, i) => Array.from({ length: n }, (_, j) => neutral));
  for (let j = 0; j < n; j++) {
    const xj = await randomScalar();
    for (let i = 0; i < m; i++) {
      const uij = await randomPoint();
      vs[i] = await operate(vs[i], await exp(uij, xj));
      us[i][j] = uij;
    }
    witness[j] = xj;
  }
  return [witness, { us, vs }];
}


/** Create dlog pair with non-uniform logarithm */
export async function createAndDlogPairs<P extends Point>(
  ctx: Group<P>,
  nrPairs: number,
): Promise<[bigint[], DlogPair<P>[]]>{
  const { randomScalar, randomPoint, exp } = ctx;
  const witness = new Array(nrPairs);
  const pairs = new Array(nrPairs);
  for (let i = 0; i < nrPairs; i++) {
    const x = await randomScalar();
    const u = await randomPoint();
    const v = await exp(u, x);
    witness[i] = x;
    pairs[i] = { u, v };
  }
  return [witness, pairs];
}


/** Creates dlog pairs with uniform logarithm */
export async function createEqDlogPairs<P extends Point>(
  ctx: Group<P>,
  nrPairs: number
): Promise<[bigint, DlogPair<P>[]]> {
  const { randomScalar, randomPoint, exp } = ctx;
  const x = await randomScalar();
  const pairs = [];
  for (let i = 0; i < nrPairs; i++) {
    const u = await randomPoint();
    const v = await exp(u, x);
    pairs.push({ u, v });
  }
  return [x, pairs];
}


/** Create single dlog pair */
export async function createDlogPair<P extends Point>(
  ctx: Group<P>,
  x?: bigint,
): Promise<[bigint, DlogPair<P>]> {
  const { randomScalar, randomPoint, exp } = ctx;
  x = x || await randomScalar();
  const u = await randomPoint();
  const v = await exp(u, x);
  return [x, { u, v }];
}


/** Create DDH-tuple */
export async function createDDHTuple<P extends Point>(
  ctx: Group<P>,
  z?: bigint
): Promise<[bigint, DDHTuple<P>]> {
  const { randomScalar, randomPoint, exp, generator: g } = ctx;
  z = z || await randomScalar();
  const u = await randomPoint();
  const v = await exp(g, z);
  const w = await exp(u, z);
  return [z, { u, v, w }];
}


/** Create point representation based on Pedersen commitment */
export async function createRepresentation<P extends Point>(
  ctx: Group<P>,
  h: P,
  s?: bigint,
  t?: bigint,
): Promise<[{ s: bigint, t: bigint }, { h: P, u: P }]> {
  const { randomScalar, exp, operate, generator: g } = ctx;
  s = s || await randomScalar();
  t = t || await randomScalar();
  const u = await operate(await exp(g, s), await exp(h, t))
  return [{ s, t }, { h, u }];
}
