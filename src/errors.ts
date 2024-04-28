enum ErrorMessages {
  AES_DECRYPTION_FAILURE = 'AES decryption failure',
  DIFFERENT_ORDERS_CANNOT_ADD = 'Cannot add polynomials with different orders',
  DIFFERENT_ORDERS_CANNOT_MULTIPLY = 'Cannot multiply polynomials with different orders',
  INSUFFICIENT_NR_SHARES = 'Insufficient number of shares',
  INTERPOLATION_NR_POINTS_EXCEEDS_ORDER = 'Number of provided points exceeds order',
  INTERPOLATION_NON_DISTINCT = 'Not all provided x\'s are distinct modulo order',
  INVALID_BYTELENGTH = 'Bytelength exceeds range',
  INVALID_ENCRYPTION = 'Invalid encryption',
  INVALID_DECRYPTOR = 'Invalid decryptor',
  INVALID_IV_LENGTH = 'Invalid IV length',
  INVALID_KEY_LENGTH = 'Invalid key length',
  INVALID_MAC = 'Invalid MAC',
  INVALID_PARTIAL_DECRYPTOR = 'Invalid partial decryptor',
  INVALID_POINT = 'Point not in subgroup',
  INVALID_SCALAR = 'Scalar not in range',
  INVALID_SECRET = 'Invalid proof of secret',
  INVALID_SHARE = 'Invalid share',
  INVALID_SIGNATURE = 'Invalid signature',
  INVERSE_NOT_EXISTS = 'No inverse exists for provided modulo',
  MISSING_AUTHENTICATION_TAG = 'Missing authentication tag',
  MODULUS_NOT_ABOVE_TWO = 'Modulus must be > 2',
  NON_POSITIVE_DEGREE = 'Polynomial degree must be positive',
  NON_POSITIVE_INPUTS = 'Non-positive inputs',
  NR_PREDEFINED_VIOLATES_THRESHOLD = 'Number of predefined points violates threshold',
  NR_SHARES_BELOW_ONE = 'Number of shared must be at least 1',
  NR_SHARES_VIOLATES_ORDER = 'Number of shares must be less than the group order',
  ORDER_NOT_ABOVE_ONE = 'Order must be > 1',
  THRESHOLD_BELOW_ONE = 'Threshold parameter must be at least 1',
  THRESHOLD_EXCEEDS_NR_SHARES = 'Threshold parameter exceeds number of shares',
  UNSUPPORTED_GROUP = 'Unsupported group'
}

export { ErrorMessages }