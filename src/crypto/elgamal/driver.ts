import { Point, Group } from '../../backend/abstract';
import { ElgamalScheme, AesMode, Algorithm } from '../../types';
import { ElgamalSchemes } from '../../enums';
import { leInt2Buff } from '../bitwise';
import { IesAlpha, KemAlpha } from './ciphers';
import { plain, kem, ies } from './ciphers';


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
    const pub = ctx.unpack(pubBytes);
    await ctx.validatePoint(pub);
    const { ciphertext, randomness, decryptor } = await plain(ctx).encrypt(
      message, pub
    );
    const { alpha, beta } = ciphertext;
    return {
      ciphertext: {
        alpha: alpha.toBytes(),
        beta: beta.toBytes(),
      },
      randomness: leInt2Buff(randomness),
      decryptor: decryptor.toBytes(),
    }
  }

  decrypt_PLAIN = async (ciphertext: PlainCiphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    const ctx = this.ctx;
    const { alpha, beta } = ciphertext;
    return plain(ctx).decrypt(
      {
        alpha: ctx.unpack(alpha),
        beta: ctx.unpack(beta),
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
    return plain(ctx).decryptWithDecryptor(
      {
        alpha: ctx.unpack(alpha),
        beta: ctx.unpack(beta),
      },
      ctx.unpack(decryptor),
    );
  }

  encrypt_KEM = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: KemCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const { ctx, mode } = this;
    const pub = ctx.unpack(pubBytes);
    await ctx.validatePoint(pub);
    const { ciphertext, randomness, decryptor } = await kem(ctx, mode).encrypt(
      message, pub
    );
    const { alpha, beta } = ciphertext;
    return {
      ciphertext: {
        alpha, beta: beta.toBytes()
      },
      randomness: leInt2Buff(randomness),
      decryptor: decryptor.toBytes(),
    }
  }

  decrypt_KEM = async (ciphertext: KemCiphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    const { ctx, mode } = this;
    const { alpha, beta } = ciphertext;
    return kem(ctx, mode).decrypt(
      {
        alpha, beta: ctx.unpack(beta)
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
    return kem(ctx, mode).decryptWithDecryptor(
      {
        alpha, beta: ctx.unpack(beta),
      },
      ctx.unpack(decryptor),
    );
  }

  encrypt_IES = async (message: Uint8Array, pubBytes: Uint8Array): Promise<{
    ciphertext: IesCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const { ctx, mode, algorithm } = this;
    const pub = ctx.unpack(pubBytes);
    await ctx.validatePoint(pub);
    const { ciphertext, randomness, decryptor } = await ies(ctx, mode, algorithm).encrypt(
      message, pub
    );
    const { alpha, beta } = ciphertext;
    return {
      ciphertext: {
        alpha, beta: beta.toBytes()
      },
      randomness: leInt2Buff(randomness),
      decryptor: decryptor.toBytes(),
    }
  }

  decrypt_IES = async (
    ciphertext: IesCiphertext,
    secret: bigint
  ): Promise<Uint8Array> => {
    const { ctx, mode, algorithm } = this;
    const { alpha, beta } = ciphertext;
    return ies(ctx, mode, algorithm).decrypt(
      {
        alpha, beta: ctx.unpack(beta)
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
    return ies(ctx, mode, algorithm).decryptWithDecryptor(
      {
        alpha, beta: ctx.unpack(beta),
      },
      ctx.unpack(decryptor),
    );
  }
}
