import { Algorithms, Systems, } from 'vsslib/enums';
import { Algorithm, System } from 'vsslib/types';
import { removeItem } from './utils';

const __algorithms = removeItem([...Object.values(Algorithms)], Algorithms.DEFAULT);
const __nrShares  = 3;
const __threshold = 2;

export const resolveTestConfig = () => {
  const algorithms = process.env.ALGORITHM ? [process.env.ALGORITHM as Algorithm] : __algorithms;
  const systems = process.env.SYSTEM ? [process.env.SYSTEM as System] : [...Object.values(Systems)];
  const nrShares = process.env.NR_SHARES ? parseInt(process.env.NR_SHARES) : __nrShares;
  const threshold = process.env.THRESHOLD ? parseInt(process.env.THRESHOLD) : __threshold;
  return {
    algorithms,
    systems,
    nrShares,
    threshold
  }
}
