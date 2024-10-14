// TODO: browser
import { randomBytes as _randomBytes } from 'node:crypto'

const NONCE_DEFAULT_SIZE = 16;

export const randomBytes = (nrBytes: number): Uint8Array =>
  Uint8Array.from(_randomBytes(nrBytes))

export const randomNonce = (nrBytes?: number): Uint8Array =>
  Uint8Array.from(_randomBytes(nrBytes || NONCE_DEFAULT_SIZE))

