import { AesModes, Algorithms, Encodings, Systems, ElgamalSchemes } from '../src/enums';
import { AesMode, Algorithm, Encoding, System, ElgamalScheme } from '../src/types';
import { removeItem } from './helpers';

const __aesModes    = removeItem([...Object.values(AesModes)], AesModes.DEFAULT);
const __algorithms  = removeItem([...Object.values(Algorithms)], Algorithms.DEFAULT);
const __schemes     = removeItem([...Object.values(ElgamalSchemes)], ElgamalSchemes.DEFAULT);
const __nrShares    = 3;
const __threshold   = 2;

export const resolveTestConfig = () => {
  const aesModes = process.env.AES_MODE ? [process.env.AES_MODE as AesMode] : __aesModes;
  const algorithms = process.env.ALGORITHM ? [process.env.ALGORITHM as Algorithm] : __algorithms;
  const schemes = process.env.SCHEME ? [process.env.SCHEME as ElgamalScheme] : __schemes;
  const encodings = [...Object.values(Encodings)]
  const systems = process.env.SYSTEM ? [process.env.SYSTEM as System] : [...Object.values(Systems)];
  const system = process.env.SYSTEM ? process.env.SYSTEM as System : Systems.ED25519;
  const nrShares = process.env.NR_SHARES ? parseInt(process.env.NR_SHARES) : __nrShares;
  const threshold = process.env.THRESHOLD ? parseInt(process.env.THRESHOLD) : __threshold;
  return {
    aesModes,
    algorithms,
    schemes,
    encodings,
    systems,
    system,
    nrShares,
    threshold
  }
}
