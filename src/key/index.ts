import { Key, SerializedKey } from './private';
import { Public, SerializedPublic } from './public';

import { Label } from '../types';
import { assertLabel } from '../utils/checkers';
import { Point } from '../backend/abstract';
const backend = require('../backend');


async function generate(label: Label): Promise<Key<Point>> {
  assertLabel(label);
  const ctx = backend.initGroup(label);
  const secret = await ctx.randomScalar();
  return new Key(ctx, secret);
}

function deserialize(serialized: SerializedKey | SerializedPublic): Key<Point> | Public<Point> {
  const { value, system: label } = serialized;
  const ctx = backend.initGroup(label);
  return typeof value == 'bigint' ?
    new Key(ctx, value) :
    new Public(ctx, ctx.unhexify(value));
}

export {
  Key,
  Public,
  generate,
  deserialize,
}
