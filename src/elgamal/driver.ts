import { Point, Group } from '../backend/abstract';
import { leInt2Buff } from '../arith';
import { ElgamalScheme, AesMode, Algorithm } from '../types';
import { ElgamalSchemes } from '../enums';

import { IesAlpha, KemAlpha, plainElgamal, iesElgamal, kemElgamal } from './core';


type IesCiphertext    = { alpha: IesAlpha, beta: Uint8Array };
type KemCiphertext    = { alpha: KemAlpha, beta: Uint8Array };
type PlainCiphertext  = { alpha: Uint8Array, beta: Uint8Array };

export type Ciphertext =
  IesCiphertext |
  KemCiphertext |
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
      case ElgamalSchemes.KEM:
        return this.encrypt_KEM(message, pubBytes);
      case ElgamalSchemes.IES:
        return this.encrypt_IES(message, pubBytes);
    }
  }

  decrypt = async (ciphertext: Ciphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    switch (this.scheme) {
      case ElgamalSchemes.IES:
        return this.decrypt_IES(
          ciphertext as IesCiphertext,
          secret,
        );
      case ElgamalSchemes.KEM:
        return this.decrypt_KEM(
          ciphertext as KemCiphertext,
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
      case ElgamalSchemes.IES:
        return this.decryptWithDecryptor_IES(
          ciphertext as IesCiphertext,
          decryptor,
        );
      case ElgamalSchemes.KEM:
        return this.decryptWithDecryptor_KEM(
          ciphertext as KemCiphertext,
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

  encrypt_KEM = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: KemCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const { ctx, mode } = this;
    const pub = await ctx.unpackValid(pubBytes);
    const { ciphertext, randomness, decryptor } = await kemElgamal(ctx, mode).encrypt(
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

  decrypt_KEM = async (ciphertext: KemCiphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    const { ctx, mode } = this;
    const { alpha, beta } = ciphertext;
    return kemElgamal(ctx, mode).decrypt(
      {
        alpha,
        beta,
      },
      secret
    );
  }

  decryptWithDecryptor_KEM = async (
    ciphertext: KemCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const { ctx, mode } = this;
    const { alpha, beta } = ciphertext;
    return kemElgamal(ctx, mode).decryptWithDecryptor(
      {
        alpha,
        beta,
      },
      decryptor,
    );
  }

  encrypt_IES = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: IesCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const { ctx, mode, algorithm } = this;
    const pub = await ctx.unpackValid(pubBytes);
    const { ciphertext, randomness, decryptor } = await iesElgamal(ctx, mode, algorithm).encrypt(
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

  decrypt_IES = async (
    ciphertext: IesCiphertext,
    secret: bigint
  ): Promise<Uint8Array> => {
    const { ctx, mode, algorithm } = this;
    const { alpha, beta } = ciphertext;
    return iesElgamal(ctx, mode, algorithm).decrypt(
      {
        alpha,
        beta,
      },
      secret
    );
  }

  decryptWithDecryptor_IES = async (
    ciphertext: IesCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const { ctx, mode, algorithm } = this;
    const { alpha, beta } = ciphertext;
    return iesElgamal(ctx, mode, algorithm).decryptWithDecryptor(
      {
        alpha,
        beta,
      },
      decryptor,
    );
  }
}
