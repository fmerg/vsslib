import { Algorithm, SignatureSchemes, SignatureScheme } from '../../schemes';
import { Point, Group } from '../../backend/abstract';
import { Signer } from './base';
import { SchnorrSigner } from './schnorr';

export default function<P extends Point, S>(
  ctx: Group<P>,
  scheme: SignatureScheme,
  algorithm: Algorithm,
) {
  if (scheme == SignatureSchemes.SCHNORR) return new SchnorrSigner(ctx, algorithm);
  throw new Error('Not implemented');
}
