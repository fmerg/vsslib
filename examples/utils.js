const commander = require('commander');

const isEqualSecret = (ctx, lhs, rhs) => ctx.leBuff2Scalar(lhs) == ctx.leBuff2Scalar(rhs);

const isEqualBuffer = (a, b) => {
  if (a.length != b.length) return false;
  for (let i = 0; i < a.length; i++)
    if (a[i] != b[i]) return false;
  return true;
}

const parseDecimal = (value) => {
  const parsedValue = parseInt(value, 10);
  if (isNaN(parsedValue)) {
    throw new commander.InvalidArgumentError('Not a number.');
  }
  return parsedValue;
}

const parseCommaSeparatedDecimals = (values) => {
  return values.split(',').map(v => parseDecimal(v))
}

exports.isEqualSecret = isEqualSecret;
exports.isEqualBuffer = isEqualBuffer;
exports.parseDecimal = parseDecimal;
exports.parseCommaSeparatedDecimals = parseCommaSeparatedDecimals;
