import {
  ElgamalSchemes, ElgamalScheme,
  AesMode, AesModes,
  Algorithms, Algorithm,
} from '../../schemes';
import { Ciphertext, BaseCipher } from './base';
import { Point, Group } from '../../backend/abstract';
import { PlainCiphertext } from '../elgamal/plain';
import { KemCiphertext } from '../elgamal/kem';
import { IesCiphertext } from '../elgamal/ies';
import plain from './plain';
import kem from './kem';
import ies from './ies';


export {
  Ciphertext,
  plain,
  kem,
  ies,
};

export type ElgamalCiphertext<P extends Point> =
  PlainCiphertext<P> |
  KemCiphertext<P> |
  IesCiphertext<P>;

export default function<P extends Point>(
  ctx: Group<P>,
  scheme: ElgamalScheme,
  mode?: AesMode,
  algorithm?: Algorithm,
) {
  switch (scheme) {
    case ElgamalSchemes.PLAIN:
      return plain(ctx);
    case ElgamalSchemes.KEM:
      if (!mode) throw new Error('AES mode required for KEM encryption')
      return kem(ctx, mode);
    case ElgamalSchemes.IES:
      if (!mode) throw new Error('AES mode required for IES encryption')
      if (!algorithm) throw new Error('Hash algorithm required for IES encryption')
      return ies(ctx, mode, algorithm);
  }
}
