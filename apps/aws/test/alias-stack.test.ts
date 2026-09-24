import assert from "node:assert/strict";
import test from "node:test";

import { App } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";

import { AliasStack } from "../lib/alias-stack.js";

void test("synthesizes an account-neutral staged stack", () => {
  const stack = new AliasStack(new App(), "alias-test-dev", { stage: "test-dev" });

  Template.fromStack(stack).templateMatches({
    Description: "Alias encrypted synchronization (test-dev)"
  });
  assert.equal(stack.tags.tagValues()["alias:stage"], "test-dev");
  assert.equal(stack.stackName, "alias-test-dev");
});

void test("rejects invalid stage names before synthesis", () => {
  assert.throws(
    () => new AliasStack(new App(), "alias-invalid", { stage: "Production" }),
    /stage must be 2-20 lowercase letters, numbers, or hyphens/
  );
});
