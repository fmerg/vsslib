import { backend } from '../src';
import { Systems } from '../src/enums';
import { Polynomial } from '../src/lagrange/core';
import { Messages } from '../src/lagrange/enums';
import { byteLen, randBigint } from '../src/utils';
import { cartesian } from './helpers';


const __0n = BigInt(0);
const __1n = BigInt(1);
const __labels = Object.values(Systems);


describe('construction', () => {
  it.each(__labels)('%s', async (label) => {
    const ctx = backend.initGroup(label);
    const coeffs = [];
    for (let i = 0; i < 5; i++) {
      coeffs.push(await ctx.randomScalar());
    }
    const polynomial = new Polynomial(ctx, coeffs);
  });
});
