import { Label } from '../types';
import { byteLen, randBigint, mod } from '../utils';
import { Messages } from './enums';

const __0n = BigInt(0);
const __1n = BigInt(1);


export class BasePolynomial {
  _coeffs: bigint[];
  _order: bigint;

  constructor(coeffs: (bigint | number)[], order: bigint | number) {
    const _order = BigInt(order);
    if ((_order <= __1n)) throw new Error(Messages.ORDER_MUST_BE_GT_ONE);
    const _coeffs: bigint[] = coeffs.map((num) => mod(BigInt(num), _order));
    let len = _coeffs.length;
    if (len > 0) {
      while (_coeffs[len - 1] === __0n) len--;
    }
    this._coeffs = _coeffs.slice(0, len);
    this._order = _order;
  }

  public get coeffs(): bigint[] {
    return this._coeffs;
  }

  public get degree(): number {
    const len = this._coeffs.length;
    return len === 0 ? -Infinity : len - 1;
  }

  public get order(): bigint {
    return this._order;
  }

  static zero = (opts: { order: bigint | number }): BasePolynomial => {
    return new BasePolynomial([], opts.order);
  }

  hasEqualCoeffs = (other: BasePolynomial): boolean => {
    const minDegree = Math.min(this.degree, other.degree);
    let index = 0;
    let flag = true;
    while (index < minDegree + 1) {
      flag &&= (this._coeffs[index] === other.coeffs[index]);
      index++;
    }
    flag &&= this.degree === other.degree;
    return flag;
  }

  isEqual = (other: BasePolynomial): boolean => {
    let flag = true;
    flag &&= this.hasEqualCoeffs(other);
    flag &&= this._order === other.order;
    return flag;
  }

  isZero = (): boolean => {
    return this._coeffs.length === 0;
  }

  clone = (): BasePolynomial => {
    return new BasePolynomial([...this._coeffs], this._order);
  }

  add = (other: BasePolynomial): BasePolynomial => {
    if (this._order !== other.order) throw new Error(Messages.DIFFERENT_ORDERS_CANNOT_ADD);
    const [long, short] = this.degree > other.degree ? [this, other] : [other, this];
    if (short.isZero()) return long.clone();
    let newCoeffs = new Array(long.degree).fill(__0n);
    for (let i = 0; i < short.degree + 1; i++) {
      newCoeffs[i] = short.coeffs[i] + long.coeffs[i];
    }
    for (let i = short.degree + 1; i < long.degree + 1; i++) {
      newCoeffs[i] = long.coeffs[i];
    }
    return new BasePolynomial(newCoeffs, this._order);
  }

  mult = (other: BasePolynomial): BasePolynomial => {
    if (this._order !== other.order) throw new Error(Messages.DIFFERENT_ORDERS_CANNOT_MULTIPLY);
    if (this.isZero() || other.isZero()) return new BasePolynomial([], this.order);
    const [long, short] = this.degree > other.degree ? [this, other] : [other, this];
    let newCoeffs = new Array(long.degree + short.degree + 1).fill(__0n);
    for (let i = 0; i < long.degree + 1; i++) {
      for (let j = 0; j < short.degree + 1; j++) {
        newCoeffs[i + j] += long.coeffs[i] * short.coeffs[j];
      }
    }
    return new BasePolynomial(newCoeffs, this._order);
  }

  multScalar = (scalar: bigint | number): BasePolynomial => {
    const s = mod(BigInt(scalar), this._order);
    return new BasePolynomial(this._coeffs.map((coeff) => s * coeff), this._order);
  }

  evaluate = (value: bigint | number): bigint => {
    const x = BigInt(value);
    const acc = this._coeffs.reduce((acc, c, i) => acc + c * x ** BigInt(i), __0n);
    return mod(acc, this._order);
  }
}
