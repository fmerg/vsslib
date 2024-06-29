import {
  BlockModes,
  Algorithms,
  Encodings,
  Systems,
  ElgamalSchemes,
  SignatureSchemes,
} from '../src/enums';
import {
  BlockMode,
  Algorithm,
  Encoding,
  System,
  ElgamalScheme,
  SignatureScheme,
} from '../src/types';
import { removeItem } from './utils';

const __modes = removeItem([...Object.values(BlockModes)], BlockModes.DEFAULT);
const __algorithms = removeItem([...Object.values(Algorithms)], Algorithms.DEFAULT);
const __elgamalSchemes = removeItem([...Object.values(ElgamalSchemes)], ElgamalSchemes.DEFAULT);
const __signatureSchemes = removeItem([...Object.values(SignatureSchemes)], SignatureSchemes.DEFAULT);
const __nrShares  = 3;
const __threshold = 2;

export const resolveTestConfig = () => {
  const modes = process.env.AES_MODE ? [process.env.AES_MODE as BlockMode] : __modes;
  const algorithms = process.env.ALGORITHM ? [process.env.ALGORITHM as Algorithm] : __algorithms;
  const elgamalSchemes = process.env.ELGAMAL_SCHEME ? [process.env.ELGAMAL_SCHEME as ElgamalScheme] : __elgamalSchemes;
  const signatureSchemes = process.env.SIGNATURE_SCHEME ? [process.env.SIGNATURE_SCHEME as SignatureScheme] : __signatureSchemes;
  const encodings = [...Object.values(Encodings)]
  const systems = process.env.SYSTEM ? [process.env.SYSTEM as System] : [...Object.values(Systems)];
  const nrShares = process.env.NR_SHARES ? parseInt(process.env.NR_SHARES) : __nrShares;
  const threshold = process.env.THRESHOLD ? parseInt(process.env.THRESHOLD) : __threshold;
  return {
    modes,
    algorithms,
    elgamalSchemes,
    signatureSchemes,
    encodings,
    systems,
    nrShares,
    threshold
  }
}
