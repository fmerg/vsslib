import { Label } from '../types';
import { assertLabel } from '../utils/checkers';
import { Cryptosystem } from './system';
import { initGroup } from './backend';


export function initCryptosystem(label: Label): Cryptosystem {
  assertLabel(label);
  const group = initGroup(label);
  return new Cryptosystem(group);
}
