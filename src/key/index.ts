import { Key } from './private';
import { Public } from './public';

import { Label } from '../types';
import { assertLabel } from '../utils/checkers';
import { Point } from '../backend/abstract';
const backend = require('../backend');


async function generate(label: Label): Promise<Key> {
  assertLabel(label);
  const ctx = backend.initGroup(label);
  const secret = await ctx.randomScalar();
  return new Key(ctx, secret);
}

export {
  Key,
  Public,
  generate,
}
