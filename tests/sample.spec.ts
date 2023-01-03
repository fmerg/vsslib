const sample = require("../dist/sample");

test("adds 1 + 2 to equal 3", () => {
  expect(sample.add(1, 2)).toBe(3);
});
