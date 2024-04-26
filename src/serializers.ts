import { Group, Point } from './backend/abstract';
import { Label, Encoding, Encodings } from './schemes';
import { PrivateKey, PublicKey } from './keys';
import { PrivateShare, PublicShare } from './sharing';
import { initGroup } from './backend';


export type SerializedPrivateKey = { value: string, system: Label, encoding: Encoding };
export type SerializedPublicKey  = { value: string, system: Label, encoding: Encoding };
export interface SerializedPrivateShare extends SerializedPrivateKey { index: number }
export interface SerializedPublicShare extends SerializedPublicKey { index: number }

export const serializePrivateKey = (
  privateKey: PrivateKey<Point>, encoding: Encoding
): SerializedPrivateKey => {
  const { ctx, bytes } = privateKey;
  const value = Buffer.from(bytes).toString(encoding);
  const system = ctx.label;
  return { value, system, encoding };
}

export const deserializePrivateKey = async (
  data: SerializedPrivateKey): Promise<PrivateKey<Point>>=> {
  const ctx = initGroup(data.system);
  const bytes = Uint8Array.from(Buffer.from(data.value, data.encoding));
  return PrivateKey.fromBytes(ctx, bytes);
}

export const serializePublicKey = (
  publicKey: PublicKey<Point>, encoding: Encoding): SerializedPublicKey => {
  const { ctx, pub } = publicKey;
  const value = encoding == Encodings.HEX ? pub.toHex() :
    Buffer.from(pub.toBytes()).toString(Encodings.BASE64);
  const system = ctx.label;
  return { value, system, encoding };
}

export const deserializePublicKey = async (
  data: SerializedPublicKey): Promise<PublicKey<Point>> => {
  const ctx = initGroup(data.system);
  const pub = data.encoding == Encodings.HEX ? ctx.unhexify(data.value) :
    ctx.unpack(Buffer.from(data.value, Encodings.BASE64));
  return PublicKey.fromPoint(ctx, pub);
}

export const serializePrivateShare = (
  privateShare: PrivateShare<Point>, encoding: Encoding): SerializedPrivateShare => {
  const { ctx, bytes, index } = privateShare;
  const value = Buffer.from(bytes).toString(encoding);
  const system = ctx.label;
  return { value, system, encoding, index };
}

export const deserializePrivateShare = async (
  data: SerializedPrivateShare): Promise<PrivateShare<Point>> => {
  const ctx = initGroup(data.system);
  const bytes = Uint8Array.from(Buffer.from(data.value, data.encoding));
  await ctx.validateBytes(bytes);
  return new PrivateShare(ctx, ctx.leBuff2Scalar(bytes), data.index);
}

export const serializePublicShare = (
  publicShare: PublicShare<Point>, encoding: Encoding): SerializedPublicShare => {
  const { ctx, pub, index } = publicShare;
  const value = encoding == Encodings.HEX ? pub.toHex() :
    Buffer.from(pub.toBytes()).toString(Encodings.BASE64);
  const system = ctx.label;
  return { value, system, encoding, index };
}

export const deserializePublicShare = async (
  data: SerializedPublicShare): Promise<PublicShare<Point>> => {
  const ctx = initGroup(data.system);
  const pub = data.encoding == Encodings.HEX ? ctx.unhexify(data.value) :
    ctx.unpack(Buffer.from(data.value, Encodings.BASE64));
  return new PublicShare(ctx, pub, data.index);
}
