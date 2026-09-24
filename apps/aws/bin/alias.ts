#!/usr/bin/env node
import { App } from "aws-cdk-lib";

import { AliasStack } from "../lib/alias-stack.js";

const app = new App();
const stage: unknown = app.node.tryGetContext("stage");

if (typeof stage !== "string" || !/^[a-z][a-z0-9-]{1,19}$/.test(stage)) {
  throw new Error("CDK context 'stage' must be 2-20 lowercase letters, numbers, or hyphens");
}

const account = process.env.CDK_DEFAULT_ACCOUNT;
const region = process.env.CDK_DEFAULT_REGION;

new AliasStack(app, `alias-${stage}`, {
  description: `Alias encrypted synchronization (${stage})`,
  ...(account !== undefined && region !== undefined ? { env: { account, region } } : {}),
  stage
});
