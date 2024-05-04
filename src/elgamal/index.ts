import { Point, Group } from '../backend/abstract';
import { ElgamalScheme, AesMode, Algorithm } from '../types';

import { Ciphertext, ElgamalDriver } from './driver';

export { Ciphertext };

export default function<P extends Point>(
  ctx: Group<P>,
  scheme: ElgamalScheme,
  algorithm: Algorithm,
  mode: AesMode,
) {
  return new ElgamalDriver(ctx, scheme, algorithm, mode)
}
