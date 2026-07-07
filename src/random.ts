// TODO: browser
import { randomBytes as _randomBytes } from 'node:crypto'

const NONCE_DEFAULT_SIZE = 16;

export function randomNonce(nrBytes?: number): Uint8Array {
  return Uint8Array.from(_randomBytes(nrBytes || NONCE_DEFAULT_SIZE));
}

