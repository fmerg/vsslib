import { System } from '../types';
import { Elliptic } from '../enums';
import { BadGroupError } from '../errors';
import { initElliptic } from './elliptic';

export { Group, Point } from './abstract'

export const initBackend = (system: System | string) => {
  system  = system as System;

  switch (system) {
    case Elliptic.ED25519:
    case Elliptic.ED448:
    case Elliptic.JUBJUB:
      return initElliptic(system);
    default:
      throw new BadGroupError(
        `Unsupported group: ${system}`
    );
  }
}
