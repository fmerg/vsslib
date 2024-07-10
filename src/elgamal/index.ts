import { Point, Group } from 'vsslib/backend';
import { ElgamalScheme, BlockMode, Algorithm } from 'vsslib/types';
import { Algorithms, BlockModes, } from 'vsslib/enums';
import { ElgamalDriver } from 'vsslib/elgamal/driver';
export { Ciphertext } from 'vsslib/elgamal/driver';

export default function <P extends Point>(
  ctx: Group<P>,
  scheme: ElgamalScheme,
  algorithm?: Algorithm,
  mode?: BlockMode,
) {
  return new ElgamalDriver(
    ctx, scheme, algorithm || Algorithms.DEFAULT, mode || BlockModes.DEFAULT
  )
}
