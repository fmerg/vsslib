import { Point, Group } from '../../backend/abstract';
import { ElgamalScheme, AesMode, Algorithm } from '../../types';

import plain from './plain';
import kem from './kem';
import ies from './ies';

import { ElgamalCiphertext, ElgamalDriver } from './driver';

export {
  plain,
  kem,
  ies,
  ElgamalCiphertext,
};

export default function<P extends Point>(
  ctx: Group<P>,
  scheme: ElgamalScheme,
  algorithm: Algorithm,
  mode: AesMode,
) {
  return new ElgamalDriver(ctx, scheme, algorithm, mode)
}
