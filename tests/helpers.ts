export const cartesian = (colls1: any[], colls2: any[]): any[] => {
  const out = [];
  for (const c1 of colls1) {
    for (const c2 of colls2) {
      out.push([c1, c2]);
    }
  }
  return out;
}
