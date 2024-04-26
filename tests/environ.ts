import {
  AesModes, AesMode,
  Algorithms, Algorithm,
  Encodings, Encoding,
  Systems, Label,
} from '../src/schemes';

const removeItem = (array: any[], item: any) => {
  const index = array.indexOf(item);
  if (index !== -1) array.splice(index, 1);
  return array;
}

const __aesModes   = removeItem([...Object.values(AesModes)], AesModes.DEFAULT);
const __algorithms = removeItem([...Object.values(Algorithms)], Algorithms.DEFAULT);

const __nrShares = 3;
const __threshold = 2;


export const resolveAesModes = (): (AesMode)[] => {
  return process.env.AES_MODE ? [process.env.AES_MODE as AesMode] : __aesModes;
}

export const resolveAlgorithms = (): (Algorithm)[] => {
  return process.env.ALGORITHM ? [process.env.ALGORITHM as Algorithm] : __algorithms;
}

export const resolveEncodings = (): (Encoding)[] => {
  return [...Object.values(Encodings)]
}

export const resolveBackends = (): (Label)[] => {
  return process.env.SYSTEM ? [process.env.SYSTEM as Label] : [...Object.values(Systems)];
}

export const resolveBackend = (): Label => {
  return process.env.SYSTEM ? process.env.SYSTEM as Label : Systems.ED25519;
}

export const resolveThresholdParams = (): { nrShares: number, threshold: number } => {
  const nrShares = process.env.NR_SHARES ? parseInt(process.env.NR_SHARES) : __nrShares;
  const threshold = process.env.THRESHOLD ? parseInt(process.env.THRESHOLD) : __threshold;
  return { nrShares, threshold };
}
