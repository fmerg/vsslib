import { Point, Group } from '../backend/abstract';
import { PrivateKey, PublicKey } from './core'
import { PartialKey, PublicKeyShare, PartialDecryptor } from './shares';

async function generateKey<P extends Point>(ctx: Group<P>): Promise<{
  privateKey: PrivateKey<P>,
  publicKey: PublicKey<P>
}> {
  const privateKey = new PrivateKey(ctx, await ctx.randomSecret());
  const publicKey = await privateKey.getPublicKey();
  return { privateKey, publicKey };
}

export {
  generateKey,
  PrivateKey,
  PublicKey,
  PartialKey,
  PublicKeyShare,
  PartialDecryptor,
}
