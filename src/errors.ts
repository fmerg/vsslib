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

/** Unknown or unsupported group, e.g. thrown by `initBackend` */
export class BadGroupError extends VssError {}

/** Bytes or point that are not a valid group element; thrown by backends and
 * reported by parsing as InvalidInput */
export class BadPointError extends VssError {}

/** Scalar out of range; thrown by backends and reported by parsing as
 * InvalidInput */
export class BadScalarError extends VssError {}

export class NoInverseError extends VssError {}

export class PolynomialError extends VssError {}

export class InterpolationError extends VssError {}

// Public errors (thrown by the public API)

/** Invalid sharing parameters or predefined shares, thrown by `shareSecret` */
export class ShamirError extends VssError {}

/** Malformed or out-of-range input, e.g. a non-canonical encoding, an invalid
 * share index or too few shares */
export class InvalidInput extends VssError {}

/** Secret share that fails verification against VSS commitments */
export class InvalidSecretShare extends VssError {}

/** Public share whose proof of knowledge fails verification */
export class InvalidPublicShare extends VssError {}
