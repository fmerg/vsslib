import { ElgamalSchemes } from '../../src/enums';
import { ElgamalScheme } from '../../src/types';
import { Point, Group } from '../../src/backend/abstract';

export const mockMessage = async (ctx: Group<Point>, scheme: ElgamalScheme) =>
  scheme == ElgamalSchemes.PLAIN ? (await ctx.randomPoint()).toBytes() :
    Uint8Array.from(Buffer.from('destroy earth'));
