import { Point, Group } from 'vsslib/backend';
import { ElgamalScheme, BlockMode, Algorithm } from 'vsslib/types';
import { ElgamalSchemes } from 'vsslib/enums';
import { DhiesAlpha, HybridAlpha, plainElgamal, dhiesElgamal, hybridElgamal } from 'vsslib/elgamal/core';


export type PlainCiphertext = { alpha: Uint8Array, beta: Uint8Array };
export type HybridCiphertext = { alpha: HybridAlpha, beta: Uint8Array };
export type DhiesCiphertext = { alpha: DhiesAlpha, beta: Uint8Array };

export type Ciphertext =
  PlainCiphertext |
  HybridCiphertext |
  DhiesCiphertext;


export class ElgamalDriver<P extends Point>{
  ctx: Group<P>;
  scheme: ElgamalScheme;
  algorithm: Algorithm;
  mode: BlockMode;

  constructor(ctx: Group<P>, scheme: ElgamalScheme, algorithm: Algorithm, mode: BlockMode) {
    this.ctx = ctx;
    this.scheme = scheme;
    this.algorithm = algorithm;
    this.mode = mode;
  }

  encrypt = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: Ciphertext
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const y = await this.ctx.unpackValid(pubBytes);
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return plainElgamal(this.ctx).encrypt(message, y);
      case ElgamalSchemes.HYBRID:
        return hybridElgamal(this.ctx, this.mode).encrypt(message, y);
      case ElgamalSchemes.DHIES:
        return dhiesElgamal(this.ctx, this.mode, this.algorithm).encrypt(
          message, y
      );
    }
  }

  decrypt = async (ciphertext: Ciphertext, secret: Uint8Array): Promise<Uint8Array> => {
    const x = this.ctx.leBuff2Scalar(secret);
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return plainElgamal(this.ctx).decrypt(
          ciphertext as PlainCiphertext, x
        );
      case ElgamalSchemes.HYBRID:
        return hybridElgamal(this.ctx, this.mode).decrypt(
          ciphertext as HybridCiphertext, x
        );
      case ElgamalSchemes.DHIES:
        return dhiesElgamal(this.ctx, this.mode, this.algorithm).decrypt(
          ciphertext as DhiesCiphertext, x
        );
      }
  }

  decryptWithDecryptor = async (
    ciphertext: Ciphertext, decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return plainElgamal(this.ctx).decryptWithDecryptor(
          ciphertext as PlainCiphertext, decryptor
        );
      case ElgamalSchemes.HYBRID:
        return hybridElgamal(this.ctx, this.mode).decryptWithDecryptor(
          ciphertext as HybridCiphertext, decryptor
        );
      case ElgamalSchemes.DHIES:
        return dhiesElgamal(this.ctx, this.mode, this.algorithm).decryptWithDecryptor(
          ciphertext as DhiesCiphertext, decryptor
        );
      }
  }

  decryptWithRandomness = async (
    ciphertext: Ciphertext, publicBytes: Uint8Array, randomness: Uint8Array
  ): Promise<Uint8Array> => {
    const y = await this.ctx.unpackValid(publicBytes);
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return plainElgamal(this.ctx).decryptWithRandomness(
          ciphertext as PlainCiphertext, y, randomness
        );
      case ElgamalSchemes.HYBRID:
        return hybridElgamal(this.ctx, this.mode).decryptWithRandomness(
          ciphertext as HybridCiphertext, y, randomness
        );
      case ElgamalSchemes.DHIES:
        return dhiesElgamal(this.ctx, this.mode, this.algorithm).decryptWithRandomness(
          ciphertext as DhiesCiphertext, y, randomness
        );
      }
  }
}
