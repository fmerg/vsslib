import { Point, Group } from '../backend';
import { ElgamalScheme, BlockMode, Algorithm } from '../types';
import { ElgamalSchemes } from '../enums';

import { DhiesAlpha, HybridAlpha, plainElgamal, dhiesElgamal, hybridElgamal } from './core';


type PlainCiphertext = { alpha: Uint8Array, beta: Uint8Array };
type HybridCiphertext = { alpha: HybridAlpha, beta: Uint8Array };
type DhiesCiphertext = { alpha: DhiesAlpha, beta: Uint8Array };

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
    const pub = await this.ctx.unpackValid(pubBytes);
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return plainElgamal(this.ctx).encrypt(message, pub);
      case ElgamalSchemes.HYBRID:
        return hybridElgamal(this.ctx, this.mode).encrypt(message, pub);
      case ElgamalSchemes.DHIES:
        return dhiesElgamal(this.ctx, this.mode, this.algorithm).encrypt(
          message, pub
      );
    }
  }

  decrypt = async (ciphertext: Ciphertext, secret: bigint): Promise<Uint8Array> => {
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return plainElgamal(this.ctx).decrypt(
          ciphertext as PlainCiphertext,
          secret
        );
      case ElgamalSchemes.HYBRID:
        return hybridElgamal(this.ctx, this.mode).decrypt(
          ciphertext as HybridCiphertext,
          secret
        );
      case ElgamalSchemes.DHIES:
        return dhiesElgamal(this.ctx, this.mode, this.algorithm).decrypt(
          ciphertext as DhiesCiphertext,
          secret
        );
      }
  }

  decryptWithDecryptor = async (
    ciphertext: Ciphertext, decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return plainElgamal(this.ctx).decryptWithDecryptor(
          ciphertext as PlainCiphertext,
          decryptor
        );
      case ElgamalSchemes.HYBRID:
        return hybridElgamal(this.ctx, this.mode).decryptWithDecryptor(
          ciphertext as HybridCiphertext,
          decryptor
        );
      case ElgamalSchemes.DHIES:
        return dhiesElgamal(this.ctx, this.mode, this.algorithm).decryptWithDecryptor(
          ciphertext as DhiesCiphertext,
          decryptor
        );
      }
  }
}
