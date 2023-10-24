// TODO: browser
import { randomBytes } from 'node:crypto';
import { leBuff2Int } from './bitwise';


export const randBigint = async (size=32): Promise<bigint> => {
  return leBuff2Int(randomBytes(size));
}
