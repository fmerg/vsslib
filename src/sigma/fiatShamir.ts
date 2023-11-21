import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { Group, Point } from '../backend/abstract';
import { leInt2Buff, leBuff2Int } from '../utils';

const utils = require('../utils');


export class FiatShamir<P extends Point>{
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm?: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm || Algorithms.DEFAULT;
  }

  async computeChallence(points: P[], scalars: bigint[], nonce?: Uint8Array, algorithm?: Algorithm): Promise<bigint> {
    const { modBytes, ordBytes, genBytes, leBuff2Scalar } = this.ctx;
    const configBuff = [...modBytes, ...ordBytes, ...genBytes];
    const pointsBuff = points.reduce((acc: number[], p: P) => [...acc, ...p.toBytes()], []);
    const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);
    nonce = nonce || Uint8Array.from([]);
    const bytes = Uint8Array.from([...configBuff, ...pointsBuff, ...scalarsBuff, ...nonce]);
    algorithm = algorithm || this.algorithm;
    const digest = await utils.hash(bytes, { algorithm });
    return leBuff2Scalar(digest);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): FiatShamir<P> {
  return new FiatShamir(ctx, algorithm);
}
