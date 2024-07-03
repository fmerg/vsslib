import { Point, Group } from 'vsslib/backend';
import { ElgamalScheme, BlockMode, Algorithm } from 'vsslib/types';
import { Algorithms, BlockModes, } from 'vsslib/enums';

import { Ciphertext, ElgamalDriver } from './driver';

export { Ciphertext };

export default function foteinos<P extends Point>(
  ctx: Group<P>,
  scheme: ElgamalScheme,
  algorithm?: Algorithm,
  mode?: BlockMode,
) {
  return new ElgamalDriver(
    ctx, scheme, algorithm || Algorithms.DEFAULT, mode || BlockModes.DEFAULT
  )
}
