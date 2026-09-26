import assert from "node:assert/strict";
import test from "node:test";

import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import type { PutCommand } from "@aws-sdk/lib-dynamodb";

import {
  DynamoSyncStore,
  SyncConflictError,
  type DynamoCommandClient
} from "../lib/dynamo-sync-store.js";

const ownerId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const record = {
  recordId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  revision: 1n,
  serverSequence: 1n,
  encryptedRecord: null,
  deleted: true
};

void test("sends a create-only ciphertext item put", async () => {
  const commands: PutCommand[] = [];
  const client: DynamoCommandClient = {
    send(command) {
      commands.push(command);
      return Promise.resolve({});
    }
  };

  await new DynamoSyncStore(client, "alias-test-sync").put(ownerId, record, null);

  const command = commands[0];
  assert.ok(command);
  assert.equal(command.input.TableName, "alias-test-sync");
  assert.equal(command.input.ConditionExpression, "attribute_not_exists(#pk)");
  const item = command.input.Item;
  assert.ok(item);
  assert.equal(item.pk, `USER#${ownerId}`);
});

void test("maps conditional failures to sync conflicts", async () => {
  const client: DynamoCommandClient = {
    send: () =>
      Promise.reject(new ConditionalCheckFailedException({ $metadata: {}, message: "conflict" }))
  };

  await assert.rejects(
    new DynamoSyncStore(client, "alias-test-sync").put(ownerId, record, null),
    SyncConflictError
  );
});
