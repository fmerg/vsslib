import { Algorithms } from '../../src/enums';
import { initGroup } from '../../src/backend';
import { cartesian } from '../helpers';
import { computeFiatShamir } from './helpers';
import { resolveTestConfig } from '../environ';

import nizk from '../../src/nizk';

let { systems, algorithms } = resolveTestConfig();



describe('Fiat-Shamir - without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points  = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const extras  = [await randomBytes(), await randomBytes()];
    const res1 = await nizk(ctx, algorithm).computeChallenge(points, scalars, extras);
    const res2 = await computeFiatShamir(ctx, algorithm, points, scalars, extras, undefined);
    expect(res1).toEqual(res2);
  });
});


describe('Fiat-Shamir - with nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const ctx = initGroup(system);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points  = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const extras  = [await randomBytes(), await randomBytes()];
    const nonce = await randomBytes();
    const res1 = await nizk(ctx, algorithm).computeChallenge(points, scalars, extras, nonce);
    const res2 = await nizk(ctx, algorithm).computeChallenge(points, scalars, extras);
    const res3 = await nizk(ctx, algorithm).computeChallenge(points, scalars, extras, await randomBytes());
    const res4 = await computeFiatShamir(ctx, algorithm, points, scalars, extras, nonce);
    expect(res1).not.toEqual(res2);
    expect(res1).not.toEqual(res3);
    expect(res1).toEqual(res4);
  });
});
