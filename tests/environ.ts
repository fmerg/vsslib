import {
  AesModes, AesMode,
  Algorithms, Algorithm,
  Encodings, Encoding,
  Systems, Label,
} from '../src/schemes';

export const resolveAesModes = (): (AesMode)[] => {
  return process.env.AES_MODE ? [process.env.AES_MODE as AesMode] : [...Object.values(AesModes)];
}

export const resolveAlgorithms = (): (Algorithm)[] => {
  return process.env.ALGORITHM ? [process.env.ALGORITHM as Algorithm] : [...Object.values(Algorithms)];
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
