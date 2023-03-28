const enums = require('../enums');

const __systems    = Object.values(enums.Systems);
const __algorithms = Object.values(enums.Algorithms);
const __encodings  = Object.values(enums.Encodings);


export const assertLabel = (label: string | number) => {
  if (!__systems.includes(label)) {
    throw new Error(`Unsupported system: ${label}`);
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
