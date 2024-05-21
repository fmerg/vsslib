const __hexLen = [0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4];


export const bitLen = (num: BigInt | bigint): number => {
  const numHex = num.toString(16);
  return (numHex.length - 1) * 4 + __hexLen[parseInt(numHex[0], 16)];
}


export const byteLen = (num: BigInt | bigint): number => {
  const nrBytes = Math.floor((bitLen(num) - 1) / 8) + 1;
  return nrBytes == 0 ? 1 : nrBytes;
}


export const leBuff2Int = (buff: Uint8Array): bigint => {
  let num = BigInt(0);
  let i = 0;
  const view = new DataView(buff.buffer, buff.byteOffset, buff.byteLength);
  while (i < buff.length) {
    if (i + 4 <= buff.length) {
      num += BigInt(view.getUint32(i, true)) << BigInt(i * 8);
      i += 4;
    } else if (i + 2 <= buff.length) {
      num += BigInt(view.getUint16(i, true)) << BigInt(i * 8);
      i += 2;
    } else {
      num += BigInt(view.getUint8(i)) << BigInt(i * 8);
      i += 1;
    }
  }
  return num;
}

export const leInt2Buff = (num: BigInt | bigint) => {
  const len = byteLen(num);
  const buff = new Uint8Array(len);
  const view = new DataView(buff.buffer);

  let i = 0;
  let r = num as bigint;
  while (i < len) {
    if (i + 4 <= len) {
      view.setUint32(i, Number(r & BigInt(0xffffffff)), true);
      i += 4;
      r = r >> BigInt(32);
    } else if (i + 2 <= len) {
      view.setUint16(i, Number(r & BigInt(0xffff)), true);
      i += 2;
      r = r >> BigInt(16);
    } else {
      view.setUint8(i, Number(r & BigInt(0xff)));
      i += 1;
      r = r >> BigInt(8);
    }
  }
  return buff;
}
