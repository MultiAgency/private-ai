import assert from "node:assert/strict";
import test from "node:test";

import { workflow } from "../site/workflow.mjs";

test("the default self-hosted workflow subscribes to /review independently of fork opt-in", () => {
  for (const forks of [false, true]) {
    const yaml = workflow({ forks, ref: "a".repeat(40) });
    assert.match(yaml, /issue_comment:\n    types: \[created\]/);
    assert.match(yaml, /pull_request:\n    types: \[opened, synchronize, ready_for_review, reopened\]/);
    assert.match(yaml, new RegExp(`allow-forks: "${forks}"`));
    assert.match(yaml, /review\/gate@a{40}/);
    assert.match(yaml, /review@a{40}/);
    assert.match(yaml, /needs: gate\n    if: needs.gate.outputs.allowed == 'true'/);
    const gate = yaml.slice(yaml.indexOf('  gate:'), yaml.indexOf('  review:'));
    assert.doesNotMatch(gate, /secrets\.|concurrency:/, "refused comments cannot load the model key or cancel active reviews");
    assert.match(gate, /pull-requests: read/);
    assert.match(gate, /github.event.issue.pull_request/);
  }
});

test("model options survive workflow generation without allowing YAML injection", () => {
  const yaml = workflow({ model: "vendor/model", unpatched: true });
  assert.match(yaml, /model: vendor\/model/);
  assert.match(yaml, /allow-unpatched-model: "true"/);
  assert.doesNotMatch(workflow({ model: "vendor/model\nmalicious: true" }), /malicious:/);
});

test("PR reviews share cancellation groups while manual setup runs remain independent", () => {
  const line = workflow().split('\n').find(line => line.trim().startsWith('group:'));
  const expression = line.match(/\$\{\{ (.+) \}\}/)[1];
  const group = new Function('github', `return (${expression});`);
  const pr = run_id => ({ run_id, event: { pull_request: { number: 7 }, issue: {} } });
  const comment = { run_id: 3, event: { pull_request: {}, issue: { number: 7 } } };
  const manual = run_id => ({ run_id, event: { pull_request: {}, issue: {} } });
  assert.equal(group(pr(1)), group(pr(2)));
  assert.equal(group(pr(1)), group(comment));
  assert.notEqual(group(manual(1)), group(manual(2)));
});
