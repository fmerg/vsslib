import { mod } from '../utils';
import { Messages } from './enums';

const __0n = BigInt(0);
const __1n = BigInt(1);


export class BasePolynomial {
  coeffs: bigint[];
  degree: number;
  order: bigint;

  constructor(coeffs: (bigint | number)[], order: bigint | number) {
    if ((order <= __1n)) throw new Error(Messages.ORDER_MUST_BE_GT_ONE);
    const reduced = coeffs.map((num) => mod(BigInt(num), BigInt(order)));
    let len = reduced.length;
    if (len > 0) {
      while (reduced[len - 1] === __0n) len--;
    }
    this.coeffs = reduced.slice(0, len);
    this.degree = len === 0 ? -Infinity : len - 1;
    this.order = BigInt(order);
  }

  static zero = (opts: { order: bigint | number }): BasePolynomial => {
    return new BasePolynomial([], opts.order);
  }

  hasEqualCoeffs = (other: BasePolynomial): boolean => {
    const minDegree = Math.min(this.degree, other.degree);
    let index = 0;
    let flag = true;
    while (index < minDegree + 1) {
      flag &&= (this.coeffs[index] === other.coeffs[index]);
      index++;
    }
    flag &&= this.degree === other.degree;
    return flag;
  }

  equals = (other: BasePolynomial): boolean => {
    let flag = true;
    flag &&= this.hasEqualCoeffs(other);
    flag &&= this.order === other.order;
    return flag;
  }

  isZero = (): boolean => {
    return this.coeffs.length === 0;
  }

  clone = (): BasePolynomial => {
    return new BasePolynomial([...this.coeffs], this.order);
  }

  add = (other: BasePolynomial): BasePolynomial => {
    if (this.order !== other.order) throw new Error(Messages.DIFFERENT_ORDERS_CANNOT_ADD);
    const [long, short] = this.degree > other.degree ? [this, other] : [other, this];
    if (short.isZero()) return long.clone();
    let newCoeffs = new Array(long.degree).fill(__0n);
    for (let i = 0; i < short.degree + 1; i++) {
      newCoeffs[i] = short.coeffs[i] + long.coeffs[i];
    }
    for (let i = short.degree + 1; i < long.degree + 1; i++) {
      newCoeffs[i] = long.coeffs[i];
    }
    return new BasePolynomial(newCoeffs, this.order);
  }

  mult = (other: BasePolynomial): BasePolynomial => {
    if (this.order !== other.order) throw new Error(Messages.DIFFERENT_ORDERS_CANNOT_MULTIPLY);
    if (this.isZero() || other.isZero()) return new BasePolynomial([], this.order);
    const [long, short] = this.degree > other.degree ? [this, other] : [other, this];
    let newCoeffs = new Array(long.degree + short.degree + 1).fill(__0n);
    for (let i = 0; i < long.degree + 1; i++) {
      for (let j = 0; j < short.degree + 1; j++) {
        newCoeffs[i + j] += long.coeffs[i] * short.coeffs[j];
      }
    }
    return new BasePolynomial(newCoeffs, this.order);
  }

  multScalar = (scalar: bigint | number): BasePolynomial => {
    const s = mod(BigInt(scalar), this.order);
    return new BasePolynomial(this.coeffs.map((coeff) => s * coeff), this.order);
  }

  evaluate = (value: bigint | number): bigint => {
    const x = BigInt(value);
    const acc = this.coeffs.reduce((acc, c, i) => acc + c * x ** BigInt(i), __0n);
    return mod(acc, this.order);
  }
}
