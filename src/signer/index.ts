import { Point, Group } from '../backend/abstract';
import { SignatureScheme, Algorithm } from '../types';

import { Signature, SigDriver } from './driver';

export { Signature };

export default function<P extends Point, S>(
  ctx: Group<P>,
  scheme: SignatureScheme,
  algorithm: Algorithm,
) {
  return new SigDriver(ctx, scheme, algorithm);
}
