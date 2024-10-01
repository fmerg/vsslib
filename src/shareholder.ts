import { Point, Group } from 'vsslib/backend';
import { mod } from 'vsslib/arith';
import { InvalidSecretShare, InvalidInput } from 'vsslib/errors';
import { SecretShare, PublicShare, SecretPacket } from 'vsslib/dealer';
import { unpackScalar, unpackPoint, extractPublic } from 'vsslib/secrets';
import { Ciphertext } from 'vsslib/elgamal';
import { NizkProof } from 'vsslib/nizk';
import { Algorithm } from 'vsslib/types';
import { Algorithms } from 'vsslib/enums';
import { InvalidDecryptor, InvalidPartialDecryptor } from 'vsslib/errors';
import { PrivateKey, PublicKey } from 'vsslib/keys/core';

import nizk from 'vsslib/nizk';


export type SchnorrPacket = PublicShare & { proof: NizkProof };
export type PartialDecryptor = { value: Uint8Array, index: number, proof: NizkProof };


export async function verifyFeldmanCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  commitments: Uint8Array[],
): Promise<boolean> {
  const { value, index } = share;
  const x = await unpackScalar(ctx, value);
  const g = ctx.generator;
  const order = ctx.order;
  const lhs = await ctx.exp(g, x);
  let rhs = ctx.neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await unpackPoint(ctx, commitment);
    const curr = await ctx.exp(c, mod(BigInt(index ** j), order));
    rhs = await ctx.operate(rhs, curr);
  }
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
  return true;
}


export async function verifyPedersenCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  binding: Uint8Array,
  publicBytes: Uint8Array,
  commitments: Uint8Array[],
): Promise<boolean> {
  const { value, index } = share;
  const exp = ctx.exp;
  const order = ctx.order;
  const g = ctx.generator;
  const h = await unpackPoint(ctx, publicBytes);
  const x = await unpackScalar(ctx, value);
  const s = await unpackScalar(ctx, binding);
  const lhs = await ctx.operate(
    await exp(g, x),
    await exp(h, s)
  );
  let rhs = ctx.neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await unpackPoint(ctx, commitment);
    const curr = await exp(c, mod(BigInt(index ** j), order));
    rhs = await ctx.operate(rhs, curr);
  }
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
  return true;
}


export async function parseFeldmanPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SecretPacket,
): Promise<{ share: SecretShare }> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmanCommitments(ctx, share, commitments);
  return { share };
}


export async function parsePedersenPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  publicBytes: Uint8Array,
  packet: SecretPacket,
): Promise<{ share: SecretShare, binding: Uint8Array }> {
  const { value, index, binding } = packet;
  if (!binding)
    throw new InvalidInput(
      `No binding found for index ${index}`
    );
  const share = { value, index }
  await verifyPedersenCommitments(
    ctx, share, binding, publicBytes, commitments,
  );
  return { share, binding };
}

export async function extractPublicShare<P extends Point>(
  ctx: Group<P>, share: SecretShare
): Promise<PublicShare> {
  const { value: secret, index } = share;
  return { value: await extractPublic(ctx, secret), index };
}


export async function createSchnorrPacket<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<SchnorrPacket> {
  const { value, index } = share;
  const g = ctx.generator;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const x = await unpackScalar(ctx, value);
  const y = await ctx.exp(g, x);
  const proof = await nizk(ctx, algorithm).proveDlog(x, { u: g, v: y }, nonce);
  return { value: y.toBytes(), index, proof };
}


export async function parsePartialKey<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SecretPacket,
  publicBytes?: Uint8Array,
): Promise<PartialKey<P>> {
  if (publicBytes) {
    const { share: { value, index } } = await parsePedersenPacket(
      ctx, commitments, publicBytes, packet,
    );
    return new PartialKey(ctx, value, index);
  } else {
    const { share: { value, index } } = await parseFeldmanPacket(
      ctx, commitments, packet
    );
    return new PartialKey(ctx, value, index);
  }
}


export class PartialKey<P extends Point> extends PrivateKey<P> {
  index: number;

  constructor(ctx: Group<P>, secret: Uint8Array, index: number) {
    super(ctx, secret);
    this.index = index;
  }

  getPublicShare = async (): Promise<PartialPublicKey<P>> => new PartialPublicKey(
    this.ctx, await extractPublic(this.ctx, this.secret), this.index
  );

  async createSchnorrPacket(opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  }): Promise<SchnorrPacket> {
    return createSchnorrPacket(this.ctx, { value: this.secret, index: this.index}, opts);
  }

  async computePartialDecryptor(
    ciphertext: Ciphertext,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array
    },
  ): Promise<PartialDecryptor> {
    const { decryptor, proof } = await this.computeDecryptor(
      ciphertext,
      opts,
    );
    return { value: decryptor, proof, index: this.index };
  }
}


export class PartialPublicKey<P extends Point> extends PublicKey<P> {
  index: number;

  constructor(ctx: Group<P>, publicBytes: Uint8Array, index: number) {
    super(ctx, publicBytes);
    this.index = index;
  }

  async verifyPartialDecryptor(
    ciphertext: Ciphertext,
    share: PartialDecryptor,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    },
  ): Promise<boolean> {
    const { value: decryptor, proof } = share;
    try {
      await this.verifyDecryptor(
        ciphertext,
        decryptor,
        proof,
        opts
      );
    } catch (err: any) {
      if (err instanceof InvalidDecryptor) throw new InvalidPartialDecryptor(
        `Invalid partial decryptor` // TODO
      );
      else throw err;
    }
    return true;
  }
}
