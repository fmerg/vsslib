import { Point, Group } from 'vsslib/backend';
import { Ciphertext } from 'vsslib/elgamal';
import { NizkProof } from 'vsslib/nizk';
import { SecretPacket, parseFeldmanPacket, parsePedersenPacket } from 'vsslib/dealer';
import { extractPublic } from 'vsslib/secrets';
import { InvalidDecryptor, InvalidPartialDecryptor } from 'vsslib/errors';
import { Algorithm } from 'vsslib/types';
import { PrivateKey, PublicKey } from 'vsslib/keys/core';


export type PartialDecryptor = { value: Uint8Array, index: number, proof: NizkProof };

export async function extractPartialKey<P extends Point>(
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
    const { value, index } = await parseFeldmanPacket(
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

  async verifyPartialDecryptor<A>(
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
