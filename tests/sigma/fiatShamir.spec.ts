import { backend } from '../../src';
import { Systems, Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { cartesian } from '../helpers';
import { fiatShamir } from '../../src/sigma';
import { computeFiatShamir } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Fiat-Shamir - without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar } = ctx;
    const points = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const res1 = await fiatShamir(ctx, algorithm).computeChallence(points, scalars);
    const res2 = await computeFiatShamir(ctx, points, scalars, { algorithm });
    expect(res1).toEqual(res2);
  });
});


describe('Fiat-Shamir - with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const nonce = await randomBytes();
    const res1 = await fiatShamir(ctx, algorithm).computeChallence(points, scalars, nonce);
    const res2 = await computeFiatShamir(ctx, points, scalars, { algorithm, nonce });
    const res3 = await fiatShamir(ctx, algorithm).computeChallence(points, scalars);
    const res4 = await fiatShamir(ctx, algorithm).computeChallence(points, scalars, await randomBytes());
    expect(res1).toEqual(res2);
    expect(res1).not.toEqual(res3);
    expect(res1).not.toEqual(res4);
  });
});
