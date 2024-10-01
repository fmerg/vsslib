import { Point, Group } from 'vsslib/backend';
import { SignatureScheme, Algorithm } from 'vsslib/types';
import { SignatureSchemes } from 'vsslib/enums';
import { SchnorrSignature } from 'vsslib/signer/schnorr';

import schnorr from 'vsslib/signer/schnorr';


export type Signature =
  SchnorrSignature;


export class SigDriver<P extends Point> {
  ctx: Group<P>;
  scheme: SignatureScheme;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, scheme: SignatureScheme, algorithm: Algorithm) {
    this.ctx = ctx;
    this.scheme = scheme;
    this.algorithm = algorithm;
  }

  signBytes = async (secret: Uint8Array, message: Uint8Array, nonce?: Uint8Array): Promise<
    Signature
  > => {
    switch (this.scheme) {
      case SignatureSchemes.SCHNORR:
        return schnorr(this.ctx, this.algorithm).signBytes(secret, message, nonce);
    }
  }

  verifyBytes = async (
    publicBytes: Uint8Array, message: Uint8Array, signature: Signature, nonce?: Uint8Array
  ): Promise<boolean> => {
    switch (this.scheme) {
      case SignatureSchemes.SCHNORR:
        return schnorr(this.ctx, this.algorithm).verifyBytes(
          publicBytes,
          message,
          signature as SchnorrSignature,
          nonce
        );
    }
  }
}
