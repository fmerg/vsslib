const commander = require('commander');

exports.parseDecimal = (value) => {
  const parsedValue = parseInt(value, 10);
  if (isNaN(parsedValue)) {
    throw new commander.InvalidArgumentError('Not a number.');
  }
  return parsedValue;
}

exports.parseCommaSeparatedDecimals = (values) => {
  return values.split(',').map(v => parseDecimal(v))
}
