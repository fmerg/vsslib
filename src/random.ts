import { randomBytes } from '@noble/hashes/utils.js';

import { InvalidInput } from './errors';

const NONCE_DEFAULT_SIZE = 16;
// SECURITY! quota of crypto.getRandomValues per call
const NONCE_MAX_SIZE = 65536;

/** Random nonce of `nrBytes` bytes, sampled with crypto.getRandomValues */
export function randomNonce(nrBytes: number = NONCE_DEFAULT_SIZE): Uint8Array {
  if (!(Number.isSafeInteger(nrBytes) && 0 < nrBytes && nrBytes <= NONCE_MAX_SIZE))
    throw new InvalidInput(
      `Nonce size must be an integer from 1 to ${NONCE_MAX_SIZE}: ${nrBytes}`
    );
  return randomBytes(nrBytes);
}
