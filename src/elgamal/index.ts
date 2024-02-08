import { Ciphertext } from './base';
import { ElgamalScheme } from '../types';
import { ElgamalSchemes } from '../enums';
import { Point } from '../backend/abstract';
import plain from './plain';
import kem from './kem';
import ies from './ies';


function resolveScheme<A extends object>(ciphertext: Ciphertext<A, Point>): ElgamalScheme {
  if ('algorithm' in ciphertext.alpha) return ElgamalSchemes.IES;
  if ('mode' in ciphertext.alpha) return ElgamalSchemes.KEM;
  return ElgamalSchemes.PLAIN;
};

export {
  Ciphertext,
  resolveScheme,
  plain,
  kem,
  ies,
};
