import { System } from '../types';
import { Modular } from '../enums';
import { Group, Point } from './abstract';


class ModPoint {  // implements Point
  // TODO: Implement
}

export class ModGroup { // extends Group<ModPoint>
  // TODO: Implement
}

export function initModular(system: System): any {  // ModGroup
  switch (system) {
    case Modular.BITS_2048:
    case Modular.BITS_4096:
      throw new Error('Not implemented yet');
    default:
      throw new Error(
        `Unsupported group: ${system}`
      )
  }
}
