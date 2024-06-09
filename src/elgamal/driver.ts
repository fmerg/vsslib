import { Point, Group } from '../backend/abstract';
import { leInt2Buff } from '../arith';
import { ElgamalScheme, AesMode, Algorithm } from '../types';
import { ElgamalSchemes } from '../enums';

import { DhiesAlpha, HybridAlpha, plainElgamal, dhiesElgamal, hybridElgamal } from './core';


type DhiesCiphertext    = { alpha: DhiesAlpha, beta: Uint8Array };
type HybridCiphertext    = { alpha: HybridAlpha, beta: Uint8Array };
type PlainCiphertext  = { alpha: Uint8Array, beta: Uint8Array };

export type Ciphertext =
  DhiesCiphertext |
  HybridCiphertext |
  PlainCiphertext;


export class ElgamalDriver<P extends Point>{
  ctx: Group<P>;
  scheme: ElgamalScheme;
  algorithm: Algorithm;
  mode: AesMode;

  constructor(
    ctx: Group<P>,
    scheme: ElgamalScheme,
    algorithm: Algorithm,
    mode: AesMode,
  ) {
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
    switch (this.scheme) {
      case ElgamalSchemes.PLAIN:
        return this.encrypt_PLAIN(message, pubBytes);
      case ElgamalSchemes.HYBRID:
        return this.encrypt_HYBRID(message, pubBytes);
      case ElgamalSchemes.DHIES:
        return this.encrypt_DHIES(message, pubBytes);
    }
  }

  decrypt = async (ciphertext: Ciphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    switch (this.scheme) {
      case ElgamalSchemes.DHIES:
        return this.decrypt_DHIES(
          ciphertext as DhiesCiphertext,
          secret,
        );
      case ElgamalSchemes.HYBRID:
        return this.decrypt_HYBRID(
          ciphertext as HybridCiphertext,
          secret,
        );
      case ElgamalSchemes.PLAIN:
        return this.decrypt_PLAIN(
          ciphertext as PlainCiphertext,
          secret,
        );
      }
  }

  decryptWithDecryptor = async (
    ciphertext: Ciphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    switch (this.scheme) {
      case ElgamalSchemes.DHIES:
        return this.decryptWithDecryptor_DHIES(
          ciphertext as DhiesCiphertext,
          decryptor,
        );
      case ElgamalSchemes.HYBRID:
        return this.decryptWithDecryptor_HYBRID(
          ciphertext as HybridCiphertext,
          decryptor,
        );
      case ElgamalSchemes.PLAIN:
        return this.decryptWithDecryptor_PLAIN(
          ciphertext as PlainCiphertext,
          decryptor,
        );
      }
  }

  encrypt_PLAIN = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: PlainCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const ctx = this.ctx;
    const pub = await ctx.unpackValid(pubBytes);
    const { ciphertext, randomness, decryptor } = await plainElgamal(ctx).encrypt(
      message, pub
    );
    const { alpha, beta } = ciphertext;
    return {
      ciphertext: {
        alpha,
        beta,
      },
      randomness,
      decryptor,
    }
  }

  decrypt_PLAIN = async (ciphertext: PlainCiphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    const ctx = this.ctx;
    const { alpha, beta } = ciphertext;
    return plainElgamal(ctx).decrypt(
      {
        alpha,
        beta,
      },
      secret
    );
  }

  decryptWithDecryptor_PLAIN = async (
    ciphertext: PlainCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const ctx = this.ctx;
    const { alpha, beta } = ciphertext;
    return plainElgamal(ctx).decryptWithDecryptor(
      {
        alpha,
        beta,
      },
      decryptor,
    );
  }

  encrypt_HYBRID = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: HybridCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const { ctx, mode } = this;
    const pub = await ctx.unpackValid(pubBytes);
    const { ciphertext, randomness, decryptor } = await hybridElgamal(ctx, mode).encrypt(
      message, pub
    );
    const { alpha, beta } = ciphertext;
    return {
      ciphertext: {
        alpha,
        beta,
      },
      randomness,
      decryptor,
    }
  }

  decrypt_HYBRID = async (ciphertext: HybridCiphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    const { ctx, mode } = this;
    const { alpha, beta } = ciphertext;
    return hybridElgamal(ctx, mode).decrypt(
      {
        alpha,
        beta,
      },
      secret
    );
  }

  decryptWithDecryptor_HYBRID = async (
    ciphertext: HybridCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const { ctx, mode } = this;
    const { alpha, beta } = ciphertext;
    return hybridElgamal(ctx, mode).decryptWithDecryptor(
      {
        alpha,
        beta,
      },
      decryptor,
    );
  }

  encrypt_DHIES = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: DhiesCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const { ctx, mode, algorithm } = this;
    const pub = await ctx.unpackValid(pubBytes);
    const { ciphertext, randomness, decryptor } = await dhiesElgamal(ctx, mode, algorithm).encrypt(
      message, pub
    );
    const { alpha, beta } = ciphertext;
    return {
      ciphertext: {
        alpha,
        beta,
      },
      randomness,
      decryptor,
    }
  }

  decrypt_DHIES = async (
    ciphertext: DhiesCiphertext,
    secret: bigint
  ): Promise<Uint8Array> => {
    const { ctx, mode, algorithm } = this;
    const { alpha, beta } = ciphertext;
    return dhiesElgamal(ctx, mode, algorithm).decrypt(
      {
        alpha,
        beta,
      },
      secret
    );
  }

  decryptWithDecryptor_DHIES = async (
    ciphertext: DhiesCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const { ctx, mode, algorithm } = this;
    const { alpha, beta } = ciphertext;
    return dhiesElgamal(ctx, mode, algorithm).decryptWithDecryptor(
      {
        alpha,
        beta,
      },
      decryptor,
    );
  }
}
