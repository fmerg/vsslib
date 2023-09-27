import { Label } from '../types';
import { assertLabel } from '../utils/checkers';
import { CryptoSystem } from './crypto';
import { initGroup } from './backend';


export function initCrypto(label: Label): CryptoSystem {
  assertLabel(label);
  const group = initGroup(label);
  return new CryptoSystem(group);
}
