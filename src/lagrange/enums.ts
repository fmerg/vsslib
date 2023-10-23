export enum Messages {
  ORDER_MUST_BE_GT_ONE = 'Polynomial order must be > 1',
  DEGREE_MUST_BE_GE_ZERO = 'Polynomial degree must be >= 0',
  DIFFERENT_ORDERS_CANNOT_ADD = 'Cannot add polynomials with different orders',
  DIFFERENT_ORDERS_CANNOT_MULTIPLY = 'Cannot multiply polynomials with different orders',
  INTERPOLATION_AT_LEAST_TWO_POINTS_NEEDED = 'At least two points are needed for interpolation',
  INTERPOLATION_NR_POINTS_EXCEEDS_ORDER = 'Number of provided points exceeds order',
  INTERPOLATION_NON_DISTINCT_XS = 'Not all provided x\'s are distinct modulo order',
}
