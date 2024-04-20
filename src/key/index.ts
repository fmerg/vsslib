import { Group } from '../backend/abstract';
import { PrivateKey, PrivateShare, KeySharing } from './private';
import { PublicKey, PublicShare } from './public';

import { Label } from '../schemes';
import { assertLabel } from '../utils/checkers';
import { Point } from '../backend/abstract';
const backend = require('../backend');

type KeyPair<P extends Point> = {
  privateKey: PrivateKey<P>;
  publicKey: PublicKey<P>;
  ctx?: Group<P>;
};

async function generate(label: Label): Promise<KeyPair<Point>> {
  assertLabel(label);
  const ctx = backend.initGroup(label);
  const privateKey = new PrivateKey(ctx, await ctx.randomBytes());
  const publicKey = await privateKey.publicKey();
  return { privateKey, publicKey, ctx };
}

export {
  PrivateKey,
  PublicKey,
  PrivateShare,
  PublicShare,
  KeyPair,
  KeySharing,
  generate,
}

