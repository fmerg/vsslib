import { Algorithm } from '../../types';
import { Algorithms } from '../../enums';
import { Group, Point } from '../../backend/abstract';
import { leInt2Buff, leBuff2Int } from '../../utils';
import hash from '../hash';


export class FiatShamir<P extends Point>{
  ctx: Group<P>;
  algorithm: Algorithm;

  constructor(ctx: Group<P>, algorithm?: Algorithm) {
    this.ctx = ctx;
    this.algorithm = algorithm || Algorithms.DEFAULT;
  }

  async computeChallenge(
    points: P[],
    scalars: bigint[],
    extras: Uint8Array[],
    nonce?: Uint8Array,
    algorithm?: Algorithm,
  ): Promise<bigint> {
    const { modBytes, ordBytes, genBytes, leBuff2Scalar } = this.ctx;
    const configBuff = [...modBytes, ...ordBytes, ...genBytes];
    const pointsBuff = points.reduce((acc: number[], p: P) => [...acc, ...p.toBytes()], []);
    const scalarsBuff = scalars.reduce((acc: number[], s: bigint) => [...acc, ...leInt2Buff(s)], []);
    const extrasBuff = extras.reduce((acc: number[], b: Uint8Array) => [...acc, ...b], []);
    nonce = nonce || Uint8Array.from([]);
    const bytes = Uint8Array.from([...configBuff, ...pointsBuff, ...scalarsBuff, ...extrasBuff, ...nonce]);
    algorithm = algorithm || this.algorithm;
    const digest = await hash(algorithm).digest(bytes) as Uint8Array; // TODO
    return leBuff2Scalar(digest);
  }
}

export default function<P extends Point>(ctx: Group<P>, algorithm?: Algorithm): FiatShamir<P> {
  return new FiatShamir(ctx, algorithm);
}
