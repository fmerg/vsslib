import { Algorithm } from '../types';
import { Group, Point } from '../backend/abstract';
import { NizkProtocol } from './core';

export {
  DlogPair,
  DDHTuple,
  GenericLinear,
  NizkProof,
  NizkProtocol,
} from './core';

export default function<P extends Point>(ctx: Group<P>, algorithm: Algorithm) {
  return new NizkProtocol(ctx, algorithm);
}
