#!/usr/bin/env node
import { App } from "aws-cdk-lib";

import { AliasStack } from "../lib/alias-stack.js";

const app = new App();
const stage: unknown = app.node.tryGetContext("stage");

if (typeof stage !== "string") {
  throw new Error("CDK context 'stage' is required");
}

const account = process.env.CDK_DEFAULT_ACCOUNT;
const region = process.env.CDK_DEFAULT_REGION;

new AliasStack(app, `alias-${stage}`, {
  ...(account !== undefined && region !== undefined ? { env: { account, region } } : {}),
  stage
});
