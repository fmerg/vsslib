import { PrivateKey, PrivateShare, KeyDistribution } from './private';
import { PublicKey, PublicShare } from './public';

import { Label } from '../types';
import { assertLabel } from '../utils/checkers';
import { Point } from '../backend/abstract';
const backend = require('../backend');

type KeyPair<P extends Point> = {
  privateKey: PrivateKey<P>;
  publicKey: PublicKey<P>;
};

async function generate(label: Label): Promise<KeyPair<Point>> {
  assertLabel(label);
  const ctx = backend.initGroup(label);
  const privateKey = new PrivateKey(ctx, await ctx.randomBytes());
  const publicKey = await privateKey.publicKey();
  return { privateKey, publicKey };
}

export {
  PrivateKey,
  PublicKey,
  PrivateShare,
  PublicShare,
  KeyPair,
  KeyDistribution,
  generate,
}
