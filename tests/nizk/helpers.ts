import { Point, Group } from 'vsslib/backend';
import { DlogPair, DDHTuple, GenericLinear } from 'vsslib/nizk';
import { hash } from 'vsslib/crypto';


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
