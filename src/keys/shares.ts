import { Point, Group } from '../backend/abstract';
import { Ciphertext } from '../elgamal';
import { NizkProof } from '../nizk';
import {
  PublicShare, SecretPacket, parseFeldmanPacket, parsePedersenPacket
} from '../dealer';
import { InvalidDecryptor, InvalidPartialDecryptor } from '../errors';
import { Algorithm } from '../types';
import { PrivateKey, PublicKey } from './core';


export type PartialDecryptor = { value: Uint8Array, index: number, proof: NizkProof };

export class PartialKey<P extends Point> extends PrivateKey<P> {
  index: number;

  constructor(ctx: Group<P>, bytes: Uint8Array, index: number) {
    super(ctx, bytes);
    this.index = index;
  }

  static async fromFeldmanPacket(
    ctx: Group<Point>,
    commitments: Uint8Array[],
    packet: SecretPacket
  ): Promise<PartialKey<Point>> {
    const { value, index } = await parseFeldmanPacket(ctx, commitments, packet);
    return new PartialKey(ctx, value, index);
  }

  static async fromPedersenPacket(
    ctx: Group<Point>,
    commitments: Uint8Array[],
    publicBytes: Uint8Array,
    packet: SecretPacket,
  ): Promise<PartialKey<Point>> {
    const { share: { value, index } } = await parsePedersenPacket(
      ctx,
      commitments,
      publicBytes,
      packet,
    );
    return new PartialKey(ctx, value, index);
  }

  async getPublicShare(): Promise<PublicKeyShare<P>> {
    return new PublicKeyShare(
      this.ctx, await this.getPublicBytes(), this.index
    );
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


export class PublicKeyShare<P extends Point> extends PublicKey<P> {
  index: number;

  constructor(ctx: Group<P>, bytes: Uint8Array, index: number) {
    super(ctx, bytes);
    this.index = index;
  }

  asPublicShare = (): PublicShare => {
    return {
      value: this.bytes,
      index: this.index,
    }
  }

  async verifyPartialDecryptor<A>(
    ciphertext: Ciphertext,
    decryptor: PartialDecryptor,
    opts?: {
      algorithm?: Algorithm,
      nonce?: Uint8Array,
    },
  ): Promise<boolean> {
    const { ctx, index } = this;
    const { value, proof } = decryptor;
    const nonce = opts ? opts.nonce : undefined;
    try {
      await this.verifyDecryptor(
        ciphertext,
        value,
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
