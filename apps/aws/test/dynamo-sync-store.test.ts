import assert from "node:assert/strict";
import test from "node:test";

import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { PutCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

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

function successfulClient(commands: Array<PutCommand | UpdateCommand>): DynamoCommandClient {
  return {
    send(command) {
      commands.push(command);
      return Promise.resolve(
        command instanceof UpdateCommand ? { Attributes: { server_sequence: 6 } } : {}
      );
    }
  };
}

void test("sends a create-only ciphertext item put", async () => {
  const commands: Array<PutCommand | UpdateCommand> = [];
  const client: DynamoCommandClient = {
    send(command) {
      commands.push(command);
      return Promise.resolve({});
    }
  };

  await new DynamoSyncStore(client, "alias-test-sync").put(ownerId, record, null);

  const command = commands[0];
  assert.ok(command instanceof PutCommand);
  assert.equal(command.input.TableName, "alias-test-sync");
  assert.equal(command.input.ConditionExpression, "attribute_not_exists(#pk)");
  const item = command.input.Item;
  assert.ok(item);
  assert.equal(item.pk, `USER#${ownerId}`);
});

void test("atomically allocates an owner-scoped sequence", async () => {
  let command: PutCommand | UpdateCommand | undefined;
  const client: DynamoCommandClient = {
    send(sentCommand) {
      command = sentCommand;
      return Promise.resolve({ Attributes: { server_sequence: 4 } });
    }
  };

  const sequence = await new DynamoSyncStore(client, "alias-test-sync").nextSequence(ownerId);

  assert.equal(sequence, 4n);
  assert.ok(command instanceof UpdateCommand);
  assert.deepEqual(command.input.Key, { pk: `USER#${ownerId}`, sk: "META#SYNC" });
  assert.equal(command.input.UpdateExpression, "ADD #server_sequence :one");
});

void test("rejects invalid sequence responses", async () => {
  const client: DynamoCommandClient = { send: () => Promise.resolve({ Attributes: {} }) };

  await assert.rejects(
    new DynamoSyncStore(client, "alias-test-sync").nextSequence(ownerId),
    /invalid server sequence/
  );
});

void test("applies a deletion with server-authoritative metadata", async () => {
  const commands: Array<PutCommand | UpdateCommand> = [];
  const store = new DynamoSyncStore(successfulClient(commands), "alias-test-sync");

  const result = await store.applyMutation(ownerId, record.recordId, {
    operation: "delete",
    expectedRevision: 2n
  });

  assert.deepEqual(result, { ...record, revision: 3n, serverSequence: 6n });
  assert.ok(commands[0] instanceof UpdateCommand);
  assert.ok(commands[1] instanceof PutCommand);
});

void test("applies an encrypted first revision", async () => {
  const encryptedRecord = {
    ciphertext: Uint8Array.of(1),
    wrappedRecordKey: Uint8Array.of(2),
    nonce: new Uint8Array(24),
    keyWrappingNonce: new Uint8Array(24),
    cryptoVersion: 1
  };
  const store = new DynamoSyncStore(successfulClient([]), "alias-test-sync");

  const result = await store.applyMutation(ownerId, record.recordId, {
    operation: "upsert",
    expectedRevision: null,
    encryptedRecord
  });

  assert.equal(result.revision, 1n);
  assert.equal(result.encryptedRecord, encryptedRecord);
  assert.equal(result.deleted, false);
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
