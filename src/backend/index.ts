import { Modular, Label } from '../schemes';
import { assertLabel } from '../utils/checkers';
import { Point, Group } from './abstract';
import { default as initModular } from './modular';
import { default as initElliptic } from './elliptic';

const __modular   = Object.values(Modular);


export function initGroup(label: Label): Group<Point> {
  assertLabel(label);
  return __modular.includes(label) ? initModular(label) : initElliptic(label);
}
