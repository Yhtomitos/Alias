import assert from "node:assert/strict";
import test from "node:test";

import { toSyncRecordItem, type SyncRecordValue } from "../lib/sync-item.js";

const ownerId = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";
const recordId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const encryptedRecord = {
  ciphertext: Uint8Array.from([1, 2, 3]),
  wrappedRecordKey: Uint8Array.from([4, 5]),
  nonce: new Uint8Array(24),
  keyWrappingNonce: new Uint8Array(24),
  cryptoVersion: 1,
  plaintext: "must not persist"
};

void test("maps only opaque keys, ciphertext, and sync metadata", () => {
  const item = toSyncRecordItem(ownerId, {
    recordId,
    revision: 2n,
    serverSequence: 7n,
    encryptedRecord,
    deleted: false
  });

  assert.ok(item.encrypted_record);
  assert.equal("plaintext" in item.encrypted_record, false);
  assert.deepEqual(item, {
    pk: `USER#${ownerId.toLowerCase()}`,
    sk: `RECORD#${recordId}`,
    record_id: recordId,
    revision: 2n,
    server_sequence: 7n,
    deleted: false,
    encrypted_record: {
      ciphertext: encryptedRecord.ciphertext,
      wrappedRecordKey: encryptedRecord.wrappedRecordKey,
      nonce: encryptedRecord.nonce,
      keyWrappingNonce: encryptedRecord.keyWrappingNonce,
      cryptoVersion: 1
    }
  });
  assert.equal("owner_id" in item, false);
});

void test("maps tombstones without encrypted record data", () => {
  const tombstone: SyncRecordValue = {
    recordId,
    revision: 3n,
    serverSequence: 8n,
    encryptedRecord: null,
    deleted: true
  };

  assert.equal("encrypted_record" in toSyncRecordItem(ownerId, tombstone), false);
});

void test("rejects invalid identifiers and record invariants", () => {
  assert.throws(
    () =>
      toSyncRecordItem("not-a-uuid", {
        recordId,
        revision: 1n,
        serverSequence: 1n,
        encryptedRecord,
        deleted: false
      }),
    /owner ID must be a UUID/
  );
  assert.throws(
    () =>
      toSyncRecordItem(ownerId, {
        recordId,
        revision: 0n,
        serverSequence: 1n,
        encryptedRecord,
        deleted: false
      }),
    /revision and sequence must be positive/
  );
});
