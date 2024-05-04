import { Point, Group } from '../../backend/abstract';
import { ElgamalScheme, AesMode, Algorithm } from '../../types';
import { ElgamalSchemes } from '../../enums';
import { leInt2Buff } from '../bitwise';
import {
  IesCiphertext,
  KemCiphertext,
  PlainCiphertext,
  ElgamalCiphertext,
} from './types'

import plain from './plain';
import kem from './kem';
import ies from './ies';


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
    ciphertext: ElgamalCiphertext
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const { ctx, scheme, algorithm, mode } = this;
    const pub = ctx.unpack(pubBytes);
    switch (scheme) {
      case ElgamalSchemes.PLAIN:
        return this.encrypt_PLAIN(message, pub);
      case ElgamalSchemes.KEM:
        return this.encrypt_KEM(message, pub);
      case ElgamalSchemes.IES:
        return this.encrypt_IES(message, pub);
    }
  }

  decrypt = async (ciphertext: ElgamalCiphertext, secret: bigint): Promise<
    Uint8Array
  > => {
    const { ctx, scheme, algorithm, mode } = this;
    switch (scheme) {
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
    ciphertext: ElgamalCiphertext,
    decryptor: Uint8Array,
  ): Promise<
    Uint8Array
  > => {
    const { ctx, scheme, algorithm, mode } = this;
    switch (scheme) {
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

  encrypt_PLAIN = async (
    message: Uint8Array,
    pub: P,
  ): Promise<{
    ciphertext: PlainCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const {
      ciphertext: {
        alpha,
        beta
      },
      randomness,
      decryptor
    } = await plain(this.ctx).encrypt(message, pub);
    return {
      ciphertext: {
        alpha: alpha.toBytes(),
        beta: beta.toBytes(),
      },
      randomness: leInt2Buff(randomness),
      decryptor: decryptor.toBytes(),
    }
  }

  decrypt_PLAIN = async (
    ciphertext: PlainCiphertext,
    secret: bigint
  ): Promise<Uint8Array> => {
    const { alpha: alphaBytes, beta: betaBytes } = ciphertext;
    const alpha = this.ctx.unpack(alphaBytes);
    const beta = this.ctx.unpack(betaBytes);
    return plain(this.ctx).decrypt(
      { alpha, beta }, secret
    );
  }

  decryptWithDecryptor_PLAIN = async (
    ciphertext: PlainCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const { alpha, beta } = ciphertext;
    return plain(this.ctx).decryptWithDecryptor(
      {
        alpha: this.ctx.unpack(alpha),
        beta: this.ctx.unpack(beta),
      },
      this.ctx.unpack(decryptor),
    );
  }

  encrypt_KEM = async (
    message: Uint8Array,
    pub: P,
  ): Promise<{
    ciphertext: KemCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const {
      ciphertext: {
        alpha,
        beta
      },
      randomness,
      decryptor,
    } = await kem(this.ctx, this.mode).encrypt(message, pub);
    return {
      ciphertext: { alpha, beta: beta.toBytes() },
      randomness: leInt2Buff(randomness),
      decryptor: decryptor.toBytes(),
    }
  }

  decrypt_KEM = async (
    ciphertext: KemCiphertext,
    secret: bigint
  ): Promise<Uint8Array> => {
    const { alpha, beta: betaBytes } = ciphertext;
    const beta = this.ctx.unpack(betaBytes);
    return kem(this.ctx, this.mode).decrypt(
      { alpha, beta }, secret
    );
  }

  decryptWithDecryptor_KEM = async (
    ciphertext: KemCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const { alpha, beta } = ciphertext;
    return kem(this.ctx, this.mode).decryptWithDecryptor(
      {
        alpha: alpha,
        beta: this.ctx.unpack(beta),
      },
      this.ctx.unpack(decryptor),
    );
  }

  encrypt_IES = async (
    message: Uint8Array,
    pub: P,
  ): Promise<{
    ciphertext: IesCiphertext,
    randomness: Uint8Array,
    decryptor: Uint8Array,
  }> => {
    const {
      ciphertext: { alpha, beta },
      randomness,
      decryptor,
    } = await ies(this.ctx, this.mode, this.algorithm).encrypt(message, pub);
    return {
      ciphertext: { alpha, beta: beta.toBytes() },
      randomness: leInt2Buff(randomness),
      decryptor: decryptor.toBytes(),
    }
  }

  decrypt_IES = async (
    ciphertext: IesCiphertext,
    secret: bigint
  ): Promise<Uint8Array> => {
    const { alpha, beta: betaBytes } = ciphertext;
    const beta = this.ctx.unpack(betaBytes);
    return ies(this.ctx, this.mode, this.algorithm).decrypt(
      { alpha, beta }, secret
    );
  }

  decryptWithDecryptor_IES = async (
    ciphertext: IesCiphertext,
    decryptor: Uint8Array,
  ): Promise<Uint8Array> => {
    const { alpha, beta } = ciphertext;
    return ies(this.ctx, this.mode, this.algorithm).decryptWithDecryptor(
      {
        alpha: alpha,
        beta: this.ctx.unpack(beta),
      },
      this.ctx.unpack(decryptor),
    );
  }
}
