import { assertLabel } from '../utils/checkers';
import { Label } from '../types';
import { Point, Group } from './abstract';
import { initGroup } from './backend';
import { CryptoSystem } from './core';


export function initCrypto(label: Label): CryptoSystem<Point, Group<Point>> {
  assertLabel(label);
  const group = initGroup(label);
  return new CryptoSystem(group);
}
