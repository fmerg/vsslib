import { Cryptosystem } from '../src/elgamal/system';
import { Systems } from '../src/enums';

const elgamal = require('../src/elgamal');
const backend = require('../src/elgamal/backend');

const __labels = Object.values(Systems);


describe('system initialization', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx1 = elgamal.initCryptosystem(label);
    const ctx2 = new Cryptosystem(backend.initGroup(label));
    expect(await ctx1.isEqual(ctx2)).toBe(true);
    expect(await ctx1.label).toEqual(label);
  });
});


describe('system initialization failure', () => {
  test('unsupported system', () => {
    const unsupported = 'unsupported';
    expect(() => elgamal.initCryptosystem(unsupported)).toThrow(
      `Unsupported system: ${unsupported}`
    );
  });
});


describe('system equality', () => {
  it.each(__labels)('over %s', async (label) => {
    const ctx = elgamal.initCryptosystem(label);
    expect(await ctx.isEqual(elgamal.initCryptosystem(label))).toBe(true);
    expect(await ctx.isEqual(
      elgamal.initCryptosystem(
        label == Systems.ED25519 ?
          Systems.ED448 :
          Systems.ED25519
      )
    )).toBe(false);
  });
});
