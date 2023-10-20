import { Label } from '../types';
import { Point, Group } from './abstract';
import { assertLabel } from '../utils/checkers';
import { CryptoSystem } from './crypto';
import { initGroup } from './backend';


export type Ctx = CryptoSystem<Point, Group<Point>>;

export function initCrypto(label: Label): Ctx {
  assertLabel(label);
  const group = initGroup(label);
  return new CryptoSystem(group);
}
