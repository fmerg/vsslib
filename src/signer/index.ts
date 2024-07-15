import { Point, Group } from 'vsslib/backend';
import { SignatureScheme, Algorithm } from 'vsslib/types';
import { SigDriver } from 'vsslib/signer/driver';

export { Signature } from 'vsslib/signer/driver';

export default function<P extends Point>(
  ctx: Group<P>,
  scheme: SignatureScheme,
  algorithm: Algorithm,
) {
  return new SigDriver(ctx, scheme, algorithm);
}
