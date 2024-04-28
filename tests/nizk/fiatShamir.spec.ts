import { Systems, Algorithms, Algorithm } from '../../src/schemes';
import { backend } from '../../src';
import { cartesian } from '../helpers';
import { fiatShamir } from '../../src/nizk';
import { computeFiatShamir } from './helpers';
import { resolveTestConfig } from '../environ';

let { labels, algorithms } = resolveTestConfig();



describe('Fiat-Shamir - without nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points  = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const extras  = [await randomBytes(), await randomBytes()];
    const res1 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras);
    const res2 = await computeFiatShamir(ctx, algorithm, points, scalars, extras, undefined);
    expect(res1).toEqual(res2);
  });
});


describe('Fiat-Shamir - with nonce', () => {
  it.each(cartesian([labels, algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points  = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const extras  = [await randomBytes(), await randomBytes()];
    const nonce = await randomBytes();
    const res1 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras, nonce);
    const res2 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras);
    const res3 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras, await randomBytes());
    const res4 = await computeFiatShamir(ctx, algorithm, points, scalars, extras, nonce);
    expect(res1).not.toEqual(res2);
    expect(res1).not.toEqual(res3);
    expect(res1).toEqual(res4);
  });
});
