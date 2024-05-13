import { initGroup } from '../backend';
import { System } from '../types';
import { PrivateKey, PublicKey } from './core'

const generateKey = async (system: System) => {
  const ctx = initGroup(system);
  const secretBytes = await ctx.randomScalarBuff();
  const privateKey = new PrivateKey(ctx, secretBytes);
  const publicKey = await privateKey.getPublicKey();
  return { privateKey, publicKey, ctx };
}

export {
  generateKey,
  PrivateKey,
  PublicKey,
}
