/**
 * Group interface of the backends, the built-in elliptic-curve backends, and
 * what a custom backend needs to implement it
 *
 * @module vsslib/backend
 */

import { System } from '../types';
import { Elliptic } from '../enums';
import { BadGroupError } from '../errors';
export { Group, Point, validateMultiExp } from './abstract'
export { BadPointError, BadScalarError } from '../errors';
import { initElliptic } from './elliptic';
export type { EcGroup, EcPoint } from './elliptic';

const ELLIPTIC = new Set<string>(Object.values(Elliptic));

/** Backend of a built-in system, e.g. `initBackend('ed25519')`; throws
 * BadGroupError on an unknown name */
export function initBackend(system: System | string) {
  if (ELLIPTIC.has(system)) return initElliptic(system as Elliptic);
  throw new BadGroupError(
    `Unsupported group: ${system}`
  );
}
