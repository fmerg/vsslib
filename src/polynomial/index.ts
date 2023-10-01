const __0n = BigInt(0);


export class Polynomial {
  _coeffs: bigint[];
  _degree: number;
  _order: bigint;

  constructor(coeffs: bigint[], order: bigint) {
    coeffs = coeffs.map((num) => num % order);
    let len = coeffs.length;
    if (len > 0) {
      while (coeffs[len - 1] == __0n) len--;
    }
    this._coeffs = coeffs.slice(0, len);
    this._degree = len == 0 ? -Infinity : len - 1;
    this._order = order;
  }

  public get coeffs(): bigint[] {
    return this._coeffs;
  }

  public get degree(): number {
    return this._degree;
  }

  public get order(): bigint {
    return this._order;
  }
}
