// TODO: browser
import { randomBytes as _randomBytes } from 'node:crypto'

export const randomBytes = (nrBytes: number): Uint8Array =>
  Uint8Array.from(_randomBytes(nrBytes))
