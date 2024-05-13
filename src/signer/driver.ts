import { Point, Group } from '../backend/abstract';
import { SignatureScheme, Algorithm } from '../types';
import { SignatureSchemes } from '../enums';
import { SchnorrSignature } from './schnorr';

import schnorr from './schnorr';


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

  signBytes = async (secret: bigint, message: Uint8Array, nonce?: Uint8Array): Promise<
    Signature
  > => {
    switch (this.scheme) {
      case SignatureSchemes.SCHNORR:
        return this.signBytes_SCHNORR(secret, message, nonce);
    }
  }

  verifyBytes = async (
    pubBytes: Uint8Array, message: Uint8Array, signature: Signature, nonce?: Uint8Array
  ): Promise<boolean> => {
    switch (this.scheme) {
      case SignatureSchemes.SCHNORR:
        return this.verifyBytes_SCHNORR(
          pubBytes,
          message,
          signature as SchnorrSignature,
          nonce
      );
    }
  }

  signBytes_SCHNORR = async (secret: bigint, message: Uint8Array, nonce?: Uint8Array): Promise<
    SchnorrSignature
  > => {
    return schnorr(this.ctx, this.algorithm).signBytes(secret, message, nonce);
  }

  verifyBytes_SCHNORR = async (
    pubBytes: Uint8Array, message: Uint8Array, signature: SchnorrSignature, nonce?: Uint8Array
  ): Promise<boolean> => {
    const ctx = this.ctx;
    const pub = await ctx.unpackValid(pubBytes);
    return schnorr(this.ctx, this.algorithm).verifyBytes(
      pub, message, signature, nonce
    );
  }
}
