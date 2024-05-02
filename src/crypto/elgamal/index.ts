import { Point, Group } from '../../backend/abstract';
import { ElgamalScheme, AesMode, Algorithm } from '../../types';

import plain from './plain';
import kem from './kem';
import ies from './ies';

import { ElgamalDriver } from './driver';
import { ElgamalCiphertext } from './types'

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
