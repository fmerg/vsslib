import { PrivateKey } from './private';
import { PublicKey } from './public';

import { Label } from '../types';
import { assertLabel } from '../utils/checkers';
import { Point } from '../backend/abstract';
const backend = require('../backend');


async function generate(label: Label): Promise<PrivateKey<Point>> {
  assertLabel(label);
  const ctx = backend.initGroup(label);
  const secret = await ctx.randomScalar();
  return PrivateKey.fromScalar(ctx, secret);
}

export {
  PrivateKey,
  PublicKey,
  generate,
}
