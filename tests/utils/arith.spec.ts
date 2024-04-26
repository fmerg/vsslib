import { utils } from '../../src';
import { Messages } from '../../src/utils/enums';
import { cartesian } from '../helpers';


describe('errors', () => {
  test('mod - Modulus <= 2', async () => {
    expect(() => utils.mod(1, 0)).toThrow(Messages.MODULUS_MUST_BE_GT_TWO);
    expect(() => utils.mod(1, 1)).toThrow(Messages.MODULUS_MUST_BE_GT_TWO);
  });
  test('gcd - Non-positive inputs', async () => {
    expect(() => utils.gcd(0, 1)).toThrow(Messages.NON_POSITIVE_INPUTS);
    expect(() => utils.gcd(1, 0)).toThrow(Messages.NON_POSITIVE_INPUTS);
    expect(() => utils.gcd(0, 0)).toThrow(Messages.NON_POSITIVE_INPUTS);
  });
});


describe('mod', () => {
  const fixtures = [
    [+0, 2, 0],
    [+1, 2, 1],
    [+2, 2, 0],
    [+3, 2, 1],
    [+4, 2, 0],
    [-1, 2, 1],
    [-2, 2, 0],
    [-3, 2, 1],
    [-4, 2, 0],
    [+0, 3, 0],
    [+1, 3, 1],
    [+2, 3, 2],
    [+3, 3, 0],
    [+4, 3, 1],
    [+5, 3, 2],
    [+6, 3, 0],
    [-1, 3, 2],
    [-2, 3, 1],
    [-3, 3, 0],
    [-4, 3, 2],
    [-5, 3, 1],
    [-6, 3, 0],
  ];
  it.each(fixtures)('%s, %s, %s', async (x, q, r) => {
    expect(utils.mod(BigInt(x), BigInt(q))).toBe(BigInt(r));
  })
});


describe('greatest common divisor', () => {
  const fixtures = [
    [1, 1, 1, 0, 1],
    [1, 2, 1, 0, 1],
    [2, 1, 0, 1, 1],
    [1, 3, 1, 0, 1],
    [3, 1, 0, 1, 1],
    [2, 2, 1, 0, 2],
    [2, 3, -1, 1, 1],
    [3, 2, 1, -1, 1],
    [2, 4, 1, 0, 2],
    [4, 2, 0, 1, 2],
    [3, 4, -1, 1, 1],
    [4, 3, 1, -1, 1],
    [6, 9, -1, 1, 3],
    [9, 6, 1, -1, 3],
    [8, 12, -1, 1, 4],
    [12, 8, 1, -1, 4],
    [56, 32, -1, 2, 8],
    [32, 56, 2, -1, 8],
  ];
  it.each(fixtures)('%s, %s, %s, %s, %s', async (a, b, x, y, g) => {
    expect(utils.gcd(BigInt(a), BigInt(b))).toEqual({
      x: BigInt(x),
      y: BigInt(y),
      g: BigInt(g),
    });
  })
});


describe('mod inverse', () => {
  const fixtures = [
    [+1, 2, 1],
    [+3, 2, 1],
    [-1, 2, 1],
    [-3, 2, 1],
    [+1, 3, 1],
    [+2, 3, 2],
    [+4, 3, 1],
    [+5, 3, 2],
    [-1, 3, 2],
    [-2, 3, 1],
    [-4, 3, 2],
    [-5, 3, 1],
    [+1, 4, 1],
    [+3, 4, 3],
    [-1, 4, 3],
    [-3, 4, 1],
    [+1, 5, 1],
    [+2, 5, 3],
    [+3, 5, 2],
    [+4, 5, 4],
    [-1, 5, 4],
    [-2, 5, 2],
    [-3, 5, 3],
    [-4, 5, 1],
    [+1, 6, 1],
    [+5, 6, 5],
    [-1, 6, 5],
    [-5, 6, 1],
    [+1, 7, 1],
    [+2, 7, 4],
    [+3, 7, 5],
    [+4, 7, 2],
    [+5, 7, 3],
    [+6, 7, 6],
    [-1, 7, 6],
    [-2, 7, 3],
    [-3, 7, 2],
    [-4, 7, 5],
    [-5, 7, 4],
    [-6, 7, 1],
  ];
  it.each(fixtures)('%s, %s, %s', async (x, q, r) => {
    expect(utils.modInv(BigInt(x), BigInt(q))).toBe(BigInt(r));
  })
});


describe('Inverse not exists', () => {
  const fixtures = [
    [+0, 2],
    [+2, 2],
    [+4, 2],
    [-2, 2],
    [-4, 2],
    [+0, 3],
    [+3, 3],
    [+6, 3],
    [-3, 3],
    [-6, 3],
    [+0, 4],
    [+2, 4],
    [+4, 4],
    [-2, 4],
    [-4, 4],
    [+0, 5],
    [+5, 5],
    [-5, 5],
    [+0, 6],
    [+2, 6],
    [+3, 6],
    [+4, 6],
    [+6, 6],
    [-2, 6],
    [-3, 6],
    [-4, 6],
    [-6, 6],
    [+0, 7],
    [+7, 7],
    [-7, 7],
  ];
  it.each(fixtures)('%s, %s', async (x, q) => {
    expect(() => utils.modInv(BigInt(x), BigInt(q))).toThrow(
      Messages.INVERSE_NOT_EXISTS
    );
  })
})

