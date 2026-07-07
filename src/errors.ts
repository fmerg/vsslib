/** Base class of all errors thrown by the library */
export class VssError extends Error {
  constructor(message?: string) {
    super(message);
    this.name = new.target.name;
  }
}

// Internal errors (backend and math layers)

export class ArithmeticError extends VssError {}

export class BadModulusError extends VssError {}

export class BadGroupError extends VssError {}

export class BadPointError extends VssError {}

export class BadScalarError extends VssError {}

export class NoInverseError extends VssError {}

export class PolynomialError extends VssError {}

export class InterpolationError extends VssError {}

// Public errors (thrown by the public API)

export class ShamirError extends VssError {}

export class InvalidInput extends VssError {}

export class InvalidSecretShare extends VssError {}

export class InvalidPublicShare extends VssError {}
