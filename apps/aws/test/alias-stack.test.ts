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

void test("creates an encrypted on-demand sync table", () => {
  const stack = new AliasStack(new App(), "alias-test-dev", { stage: "test-dev" });
  const template = Template.fromStack(stack);

  template.hasResourceProperties("AWS::DynamoDB::Table", {
    AttributeDefinitions: [
      { AttributeName: "pk", AttributeType: "S" },
      { AttributeName: "sk", AttributeType: "S" }
    ],
    BillingMode: "PAY_PER_REQUEST",
    KeySchema: [
      { AttributeName: "pk", KeyType: "HASH" },
      { AttributeName: "sk", KeyType: "RANGE" }
    ],
    SSESpecification: { SSEEnabled: true },
    TableName: "alias-test-dev-sync"
  });
});

void test("retains and protects the production sync table", () => {
  const stack = new AliasStack(new App(), "alias-prod", { stage: "prod" });

  Template.fromStack(stack).hasResource("AWS::DynamoDB::Table", {
    DeletionPolicy: "Retain",
    Properties: {
      DeletionProtectionEnabled: true,
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true }
    },
    UpdateReplacePolicy: "Retain"
  });
});

void test("rejects invalid stage names before synthesis", () => {
  assert.throws(
    () => new AliasStack(new App(), "alias-invalid", { stage: "Production" }),
    /stage must be 2-20 lowercase letters, numbers, or hyphens/
  );
});
