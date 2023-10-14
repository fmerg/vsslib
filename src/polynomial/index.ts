import { Label } from '../types';
import { byteLen, randomInteger, mod, modInv } from '../utils';

const __0n = BigInt(0);
const __1n = BigInt(1);


export class Polynomial {
  _coeffs: bigint[];
  _order: bigint;

  constructor(coeffs: bigint[], order: bigint) {
    if ((order <= __1n)) throw new Error('Polynomial order must be > 1');
    coeffs = coeffs.map((num) => mod(num, order));
    let len = coeffs.length;
    if (len > 0) {
      while (coeffs[len - 1] === __0n) len--;
    }
    this._coeffs = coeffs.slice(0, len);
    this._order = order;
  }

  public get coeffs(): bigint[] {
    return this._coeffs;
  }

  public get degree(): number {
    let len = this._coeffs.length;
    return len === 0 ? -Infinity : len - 1;
  }

  public get order(): bigint {
    return this._order;
  }

  static zero = (opts: { order: bigint }): Polynomial => {
    return new Polynomial([], opts.order);
  }

  static random = async (opts: { degree: number, order: bigint }): Promise<Polynomial> => {
    const { degree, order } = opts;
    if (degree < 0) throw new Error('Polynomial degree must be >= 0')
    const coeffs = new Array(degree + 1);
    const nrBytes = byteLen(order);
    for (let i = 0; i < coeffs.length; i++) {
      coeffs[i] = await randomInteger(nrBytes);
    }
    return new Polynomial(coeffs, order);
  }

  hasEqualCoeffs = (other: Polynomial): boolean => {
    const minDegree = Math.min(this.degree, other.degree);
    let index = 0;
    let flag = true;
    while (index < minDegree + 1) {
      flag &&= (this._coeffs[index] === other.coeffs[index]);
      index++;
    }
    return this.degree === other.degree ? flag : false;
  }

  isEqual = (other: Polynomial): boolean => {
    let flag = true;
    flag &&= this.hasEqualCoeffs(other);
    flag &&= this._order === other.order;
    return flag;
  }

  isZero = (): boolean => {
    return this._coeffs.length === 0;
  }

  clone = (): Polynomial => {
    return new Polynomial([...this._coeffs], this._order);
  }

  add = (other: Polynomial): Polynomial => {
    if (this._order !== other.order) throw new Error(
      'Could not add polynomials: different orders'
    );

    let [long, short] = this.degree > other.degree ? [this, other] : [other, this];
    if (short.isZero()) return long.clone();

    let newCoeffs = new Array(long.degree).fill(__0n);
    for (let i = 0; i < short.degree + 1; i++) {
      newCoeffs[i] = short.coeffs[i] + long.coeffs[i];
    }
    for (let i = short.degree + 1; i < long.degree + 1; i++) {
      newCoeffs[i] = long.coeffs[i];
    }
    return new Polynomial(newCoeffs, this._order);
  }

  mult = (other: Polynomial): Polynomial => {
    if (this._order !== other.order) throw new Error(
      'Could not multiply polynomials: different orders'
    );

    if (this.isZero() || other.isZero()) return new Polynomial([], this.order);

    let [long, short] = this.degree > other.degree ? [this, other] : [other, this];
    let newCoeffs = new Array(long.degree + short.degree + 1).fill(__0n);
    for (let i = 0; i < long.degree + 1; i++) {
      let curr_i = long.coeffs[i];
      for (let j = 0; j < short.degree + 1; j++) {
        newCoeffs[i + j] += curr_i * short.coeffs[j];
      }
    }
    return new Polynomial(newCoeffs, this._order);
  }

  multScalar = (scalar: bigint): Polynomial => {
    scalar = mod(scalar, this._order);
    return new Polynomial(this._coeffs.map((coeff) => scalar * coeff), this._order);
  }

  evaluate = (value: bigint | number): bigint => {
    const x = BigInt(value);
    const acc = this._coeffs.reduce((acc, c, i) => acc + c * x ** BigInt(i), __0n);
    return mod(acc, this._order);
  }
}
