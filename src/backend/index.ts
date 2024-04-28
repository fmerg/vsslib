import { Modular } from '../enums';
import { Label } from '../types';
import { Point, Group } from './abstract';
import { default as initModular } from './modular';
import { default as initElliptic } from './elliptic';

const __modular   = Object.values(Modular);


export function initGroup(label: Label): Group<Point> {
  return __modular.includes(label) ? initModular(label) : initElliptic(label);
}
