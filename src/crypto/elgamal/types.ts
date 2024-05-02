export type IesCiphertext = {
  alpha: {
    ciphered: Uint8Array,
    iv: Uint8Array,
    mac: Uint8Array,
    tag?: Uint8Array,
  };
  beta: Uint8Array;
}

export type KemCiphertext = {
  alpha: {
    ciphered: Uint8Array,
    iv: Uint8Array,
    tag?: Uint8Array,
  },
  beta: Uint8Array,
}

export type PlainCiphertext = {
  alpha: Uint8Array,
  beta: Uint8Array,
}

export type ElgamalCiphertext =
  IesCiphertext |
  KemCiphertext |
  PlainCiphertext;
