import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Point, Group } from '../backend/abstract';
import { DlogProtocol } from '../sigma/dlog';


export type SchnorrSignature<P extends Point> = {};


export class SchnorrSigner<P extends Point> extends DlogProtocol<P> {

  signBytes = async (secret: bigint, message: Uint8Array): Promise<SchnorrSignature<P>> => {
    return {};
  }

  verifyBytes = async (pub: P, message: Uint8Array, signature: any): Promise<boolean> => {
    return false;
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): SchnorrSigner<P> {
  return new SchnorrSigner(ctx, algorithm);
}

