import { PrivateKey, SerializedKey } from './private';
import { PublicKey, SerializedPublic } from './public';

import { Label } from '../types';
import { assertLabel } from '../utils/checkers';
import { Point } from '../backend/abstract';
const backend = require('../backend');


async function generate(label: Label): Promise<PrivateKey<Point>> {
  assertLabel(label);
  const ctx = backend.initGroup(label);
  const secret = await ctx.randomScalar();
  return new PrivateKey(ctx, secret);
}

function deserialize(
  serialized: SerializedKey | SerializedPublic
): PrivateKey<Point> | PublicKey<Point> {
  const { value, system: label } = serialized;
  const ctx = backend.initGroup(label);
  return typeof value == 'bigint' ?
    new PrivateKey(ctx, value) :
    new PublicKey(ctx, ctx.unhexify(value));
}

export {
  PrivateKey,
  PublicKey,
  generate,
  deserialize,
}
