import path from 'node:path';

// node:test reporter writing the number of tests that ran, i.e. passed or
// failed without being skipped or todo. Suites, which node also reports when
// all their tests were filtered out, and the per-file entries of process
// isolation do not count; test.sh reads the number to fail runs without tests
export default async function* countTests(source) {
  let ran = 0;
  for await (const { type, data } of source) {
    if (type !== 'test:pass' && type !== 'test:fail') continue;
    if (data.details?.type === 'suite') continue;
    if (data.skip !== undefined || data.todo !== undefined) continue;
    if (data.file && path.resolve(data.name) === data.file) continue;
    ran++;
  }
  yield `${ran}\n`;
}
