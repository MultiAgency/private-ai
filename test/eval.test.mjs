import assert from "node:assert/strict";
import test from "node:test";

import { question } from "../eval/judge.mjs";

test("a reacted finding becomes one self-contained yes/no question", () => {
  const q = question('**Bugs, Important:** `closeIfPaid` closes the job before """delivery""".');
  assert.match(q, /^Does this code review raise, as a defect, the same issue as the following finding/);
  assert.match(q, /Finding: """\*\*Bugs, Important:\*\* `closeIfPaid` closes the job before '''delivery'''\."""/);
  assert.match(q, /Answer NO if the review does not raise this issue\.$/);
});
