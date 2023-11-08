export enum Messages {
  ORDER_MUST_BE_GT_ONE = 'BasePolynomial order must be > 1',
  DEGREE_MUST_BE_GE_ZERO = 'BasePolynomial degree must be >= 0',
  DIFFERENT_ORDERS_CANNOT_ADD = 'Cannot add polynomials with different orders',
  DIFFERENT_ORDERS_CANNOT_MULTIPLY = 'Cannot multiply polynomials with different orders',
  INTERPOLATION_NR_POINTS_EXCEEDS_ORDER = 'Number of provided points exceeds order',
  INTERPOLATION_NON_DISTINCT_XS = 'Not all provided x\'s are distinct modulo order',
}
