import { Key } from '../key';
import { Point } from '../elgamal/abstract';

export type KeyShare = {
  key: Key,
  index: number,
};

export type DecryptorShare = {
  decryptor: Point,
  index: number,
  proof: any,   // TODO
};

