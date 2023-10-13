import { Label } from '../types';
import { byteLen, randomInteger } from '../utils';

const __0n = BigInt(0);
const __1n = BigInt(1);


export class Polynomial {
  _coeffs: bigint[];
  _order: bigint;

  constructor(coeffs: bigint[], order: bigint) {
    if (!(order > __1n)) throw new Error(
      `Polynomial order should be greater than 1: ${order}`
    );

    coeffs = coeffs.map((num) => num % order);
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

    if (degree < 0) throw new Error(
      `Polynomial degree should be non-negative: ${degree}`
    );

    const coeffs = new Array(degree + 1);
    const nrBytes = byteLen(order);
    for (let i = 0; i < coeffs.length; i++) {
      coeffs[i] = await randomInteger(nrBytes);
    }

    return new Polynomial(coeffs, order);
  }

  isZero = (): Boolean => {
    return this._coeffs.length === 0;
  }

  hasEqualCoeffs(other: Polynomial): Boolean {
    const minDegree = Math.min(this.degree, other.degree);
    let index = 0;
    let flag = true;
    while (index <= minDegree) {
      flag &&= (this._coeffs[index] === other.coeffs[index]);
      index++;
    }
    return this.degree === other.degree ? flag : false;
  }

  isEqual = (other: Polynomial): Boolean => {
    return (
      this._order === other.order && this.hasEqualCoeffs(other)
    );
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
    for (let i = 0; i <= short.degree; i++) {
      newCoeffs[i] = short.coeffs[i] + long.coeffs[i];
    }
    for (let i = short.degree + 1; i <= long.degree; i++) {
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
    for (let i = 0; i <= long.degree; i++) {
      let curr_i = long.coeffs[i];
      for (let j = 0; j <= short.degree; j++) {
        newCoeffs[i + j] += curr_i * short.coeffs[j];
      }
    }
    return new Polynomial(newCoeffs, this._order);
  }

  multScalar = (scalar: bigint): Polynomial => {
    return new Polynomial(this._coeffs.map((coeff) => scalar * coeff), this._order);
  }
}
