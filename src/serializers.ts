import { Group, Point } from './backend/abstract';
import { Label, Encoding } from './schemes';
import { PrivateKey, PublicKey } from './keys';
import { PrivateShare, PublicShare } from './sharing';
import { initGroup } from './backend';


export type SerializedPrivateKey = { value: string, system: Label };
export type SerializedPublicKey  = { value: string, system: Label };

export const serializePrivateKey = (privateKey: PrivateKey<Point>): SerializedPrivateKey => {
  const { ctx, bytes } = privateKey;
  const value = Buffer.from(bytes).toString('hex');  // TODO: Parametrize
  const system = ctx.label;
  return { value, system };
}

export const deserializePrivateKey = async (data: SerializedPrivateKey): Promise<PrivateKey<Point>>=> {
  const ctx = initGroup(data.system);
  const bytes = Uint8Array.from(Buffer.from(data.value, 'hex'));  // TODO: Parametrize
  return PrivateKey.fromBytes(ctx, bytes);
}

export const serializePublicKey = (publicKey: PublicKey<Point>): SerializedPublicKey => {
  const { ctx, pub } = publicKey;
  const value = pub.toHex();  // TODO: Parametrize
  const system = ctx.label;
  return { value, system };
}

export const deserializePublicKey = async (data: SerializedPublicKey): Promise<PublicKey<Point>> => {
  const ctx = initGroup(data.system);
  const pub = ctx.unhexify(data.value); // TODO: Parametrize
  return PublicKey.fromPoint(ctx, pub);
}


export interface SerializedPrivateShare extends SerializedPrivateKey { index: number }
export interface SerializedPublicShare extends SerializedPublicKey { index: number }

export const serializePrivateShare = (privateShare: PrivateShare<Point>): SerializedPrivateShare => {
  const { ctx, bytes, index } = privateShare;
  const value = Buffer.from(bytes).toString('hex');  // TODO: Parametrize
  const system = ctx.label;
  return { value, system, index };
}

export const deserializePrivateShare = async (data: SerializedPrivateShare): Promise<PrivateShare<Point>> => {
  const ctx = initGroup(data.system);
  const bytes = Uint8Array.from(Buffer.from(data.value, 'hex'));  // TODO: Parametrize
  await ctx.validateBytes(bytes);
  return new PrivateShare(ctx, ctx.leBuff2Scalar(bytes), data.index);
}

export const serializePublicShare = (publicShare: PublicShare<Point>): SerializedPublicShare => {
  const { ctx, pub, index } = publicShare;
  const value = pub.toHex();
  const system = ctx.label;
  return { value, system, index };
}

export const deserializePublicShare = async (data: SerializedPublicShare): Promise<PublicShare<Point>> => {
  const ctx = initGroup(data.system);
  const pub = ctx.unhexify(data.value); // TODO: Parametrize
  await ctx.validatePoint(pub);
  return new PublicShare(ctx, pub, data.index);
}
