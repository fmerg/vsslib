import { backend } from '../../src';
import { Systems } from '../../src/enums';
import { Polynomial, verifyFeldmannCommitments, verifyPedersenCommitments } from '../../src/polynomials';
import { Messages } from '../../src/polynomials/enums';
import { cartesian } from '../helpers';


const __0n = BigInt(0);
const __1n = BigInt(1);
const __labels = Object.values(Systems);


describe('Random polynomial generation', () => {
  test('Non-positive degree error', async () => {
    const ctx = backend.initGroup('ed25519');
    await expect(Polynomial.random(ctx, -1)).rejects.toThrow(
      Messages.DEGREE_MUST_BE_GE_ZERO
    );
  });
  test('Correct parameters', async () => {
    const ctx = backend.initGroup('ed25519');
    const degree = 7;
    const polynomial = await Polynomial.random(ctx, degree);
    expect(await polynomial.ctx.isEqual(ctx)).toBe(true);
    expect(polynomial.degree).toEqual(degree);
    expect(polynomial.coeffs.length).toEqual(degree + 1);
  });
});


describe('Algebraic operations with random poynomials', () => {
  const degree_pairs = [
    [0, 0], [0, 1], [1, 1], [0, 2], [1, 2], [2, 2], [5, 7], [6, 9], [7, 9], [8, 9]
  ];

  it.each(cartesian([degree_pairs, __labels]))('Addition with degrees %s over %s', async (
    degrees, label
  ) => {
    const ctx = backend.initGroup(label);
    let [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await Polynomial.random(ctx, degree1);
    const poly2 = await Polynomial.random(ctx, degree2);
    const poly3 = new Polynomial(
      ctx,
      poly1.coeffs.map((c: bigint, i: number) => c + poly2.coeffs[i]).concat(
        poly2.coeffs.slice(poly1.degree + 1)
      ),
    );
    expect(poly3.isEqual(poly1.add(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.add(poly1))).toBe(true);
  });

  it.each(cartesian([degree_pairs, __labels]))('Multiplication with degrees %s over %s', async (
    degrees, label
  ) => {
    const ctx = backend.initGroup(label);
    let [degree1, degree2] = degrees.sort((a: number, b: number) => a - b);
    const poly1 = await Polynomial.random(ctx, degree1);
    const poly2 = await Polynomial.random(ctx, degree2);
    let newCoeffs = new Array(degree1 + degree2 + 1).fill(__0n);
    for (let i = 0; i <= degree1; i++) {
      for (let j = 0; j <= degree2; j++) {
        newCoeffs[i + j] += poly1.coeffs[i] * poly2.coeffs[j];
      }
    }
    const poly3 = new Polynomial(ctx, newCoeffs);
    expect(poly3.isEqual(poly1.mult(poly2))).toBe(true);
    expect(poly3.isEqual(poly2.mult(poly1))).toBe(true);
  });
});


describe('Feldmann commitments - success', () => {
  const degrees = [0, 1, 2, 3, 4, 5];
  it.each(cartesian([__labels, degrees]))('degree %s over %s', async (label, degree) => {
    const ctx = backend.initGroup(label);
    const polynomial = await Polynomial.random(ctx, degree);
    const { commitments } = await polynomial.generateFeldmannCommitments();
    for (let index = 0; index < polynomial.coeffs.length; index++) {
      const secret = await polynomial.evaluate(index);
      const isValid = await verifyFeldmannCommitments(
        ctx,
        secret,
        index,
        commitments,
      );
      expect(isValid).toBe(true);
    }
  });
});

test('Feldmann commitments - failure', async () => {
  const ctx = backend.initGroup('ed25519');
  const polynomial = await Polynomial.random(ctx, 3);
  const { commitments } = await polynomial.generateFeldmannCommitments();
  for (let index = 0; index < polynomial.coeffs.length; index++) {
    const secret = await ctx.randomScalar();
    const isValid = await verifyFeldmannCommitments(
      ctx,
      secret,
      index,
      commitments,
    );
    expect(isValid).toBe(false);
  }
});


describe('Pedersen commitments - success', () => {
  const degrees = [0, 1, 2, 3, 4, 5];
  it.each(cartesian([__labels, degrees]))('degree %s over %s', async (label, degree) => {
    const ctx = backend.initGroup(label);
    const pub = await ctx.randomPoint();
    const polynomial = await Polynomial.random(ctx, degree);
    const { commitments, bindings } = await polynomial.generatePedersenCommitments(pub);
    for (const [index, binding] of bindings.entries()) {
      const secret = await polynomial.evaluate(index);
      const isValid = await verifyPedersenCommitments(
        ctx,
        secret,
        binding,
        index,
        pub,
        commitments,
      );
      expect(isValid).toBe(true);
    }
  });
});


test('Pedersen commitments - failure', async () => {
  const ctx = backend.initGroup('ed25519');
  const pub = await ctx.randomPoint();
  const polynomial = await Polynomial.random(ctx, 3);
  const { commitments, bindings } = await polynomial.generatePedersenCommitments(pub);
  for (const [index, binding] of bindings.entries()) {
    const secret = await ctx.randomScalar();
    const isValid = await verifyPedersenCommitments(
      ctx,
      secret,
      binding,
      index,
      pub,
      commitments,
    );
    expect(isValid).toBe(false);
  }
});
