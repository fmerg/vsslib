import { CryptoSystem } from '../src/elgamal/crypto';
import { Point } from '../src/elgamal/abstract';
import { Systems, Algorithms } from '../src/enums';
import { cartesian } from './helpers';

const elgamal = require('../src/elgamal');
const backend = require('../src/elgamal/backend');


const __labels      = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('crypto initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx1 = elgamal.initCrypto(label);
    const ctx2 = new CryptoSystem(backend.initGroup(label));
    expect(await ctx1.isEqual(ctx2)).toBe(true);
    expect(await ctx1.label).toEqual(label);
  });
});


describe('crypto initialization failure', () => {
  test('unsupported crypto', () => {
    const unsupported = 'unsupported';
    expect(() => elgamal.initCrypto(unsupported)).toThrow(
      `Unsupported crypto: ${unsupported}`
    );
  });
});


describe('crypto equality', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCrypto(label);
    expect(await ctx.isEqual(elgamal.initCrypto(label))).toBe(true);
    expect(await ctx.isEqual(
      elgamal.initCrypto(
        label == Systems.ED25519 ? Systems.ED448 : Systems.ED25519
      )
    )).toBe(false);
  });
});
