import { Ciphertext } from './common';
import { AsymmetricMode } from '../types';
import { AsymmetricModes } from '../enums';
import { Point } from '../backend/abstract';
import elgamal from './elgamal';
import kem from './kem';
import ies from './ies';


function resolveScheme<A extends object>(ciphertext: Ciphertext<A, Point>): AsymmetricMode {
  if ('algorithm' in ciphertext.alpha) return AsymmetricModes.IES;
  if ('mode' in ciphertext.alpha) return AsymmetricModes.KEM;
  return AsymmetricModes.ELGAMAL;
};

export {
  Ciphertext,
  resolveScheme,
  elgamal,
  kem,
  ies,
};
