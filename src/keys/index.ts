import { initBackend } from '../backend';
import { System } from '../types';
import { PrivateKey, PublicKey } from './core'
import { PrivateKeyShare, PublicKeyShare, PartialDecryptor } from './shares';

const generateKey = async (system: System) => {
  const ctx = initBackend(system);
  const privateKey = new PrivateKey(ctx, await ctx.randomSecret());
  const publicKey = await privateKey.getPublicKey();
  return { privateKey, publicKey, ctx };
}

export {
  generateKey,
  PrivateKey,
  PublicKey,
  PrivateKeyShare,
  PublicKeyShare,
  PartialDecryptor,
}
