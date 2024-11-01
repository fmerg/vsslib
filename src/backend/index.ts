import { System } from 'vsslib/types';
import { Elliptic } from 'vsslib/enums';
import { BadGroupError } from 'vsslib/errors';
export { Group, Point } from 'vsslib/backend/abstract'
import { initElliptic } from 'vsslib/backend/elliptic';

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
