import { Point, Group } from '../backend/abstract';
import { SignatureScheme, Algorithm } from '../types';
import { SignatureSchemes } from '../enums';
import { SchnorrSignature } from './signers';


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
}
