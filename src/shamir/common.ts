import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import { mod, modInv } from '../utils';
import { Messages } from './enums';


const __0n = BigInt(0);
const __1n = BigInt(1);


export abstract class Share<T> {
  value: T;
  index: number;

  constructor(value: T, index: number) {
    this.value = value;
    this.index = index;
  }
}


export function selectShare<T>(index: number, shares: Share<T>[]): Share<T> {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(Messages.NO_SHARE_WITH_INDEX);
  return selected;
}


export const computeLambda = (index: number, qualifiedIndexes: number[], order: bigint): bigint => {
  let lambda = __1n;
  const i = index;
  qualifiedIndexes.forEach(j => {
    if (i != j) {
      const curr = BigInt(j) * modInv(BigInt(j - i), order);
      lambda = mod(lambda * curr, order);
    }
  });
  return lambda;
}
