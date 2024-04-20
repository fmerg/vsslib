const schemes = require('../schemes');

const __labels     = Object.values(schemes.Systems);
const __algorithms = Object.values(schemes.Algorithms);
const __encodings  = Object.values(schemes.Encodings);


export const assertLabel = (label: string | number) => {
  if (!__labels.includes(label)) {
    throw new Error(`Unsupported crypto: ${label}`);
  }
}


export const assertAlgorithm = (algorithm: string) => {
  if (!__algorithms.includes(algorithm)) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
}


export const assertEncoding = (encoding: string) => {
  if (!__encodings.includes(encoding)) {
    throw new Error(`Unsupported encoding: ${encoding}`);
  }
}
