import { backend } from '../../../src';
import { Systems, Algorithms } from '../../../src/enums';
import { Algorithm } from '../../../src/types';
import { cartesian } from '../../helpers';
import { fiatShamir } from '../../../src/core/sigma';
import { computeFiatShamir } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];



describe('Fiat-Shamir - without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points  = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const extras  = [await randomBytes(), await randomBytes()];
    const res1 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras);
    const res2 = await computeFiatShamir(ctx, points, scalars, extras, undefined, algorithm);
    expect(res1).toEqual(res2);
  });
});


describe('Fiat-Shamir - with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { randomPoint, randomScalar, randomBytes } = ctx;
    const points  = [await randomPoint(), await randomPoint(), await randomPoint()];
    const scalars = [await randomScalar(), await randomScalar()];
    const extras  = [await randomBytes(), await randomBytes()];
    const nonce = await randomBytes();
    const res1 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras, nonce);
    const res2 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras);
    const res3 = await fiatShamir(ctx, algorithm).computeChallenge(points, scalars, extras, await randomBytes());
    const res4 = await computeFiatShamir(ctx, points, scalars, extras, nonce, algorithm);
    expect(res1).not.toEqual(res2);
    expect(res1).not.toEqual(res3);
    expect(res1).toEqual(res4);
  });
});
