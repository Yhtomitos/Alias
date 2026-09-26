const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface EncryptedRecordValue {
  readonly ciphertext: Uint8Array;
  readonly wrappedRecordKey: Uint8Array;
  readonly nonce: Uint8Array;
  readonly keyWrappingNonce: Uint8Array;
  readonly cryptoVersion: number;
}

export interface SyncRecordValue {
  readonly recordId: string;
  readonly revision: bigint;
  readonly serverSequence: bigint;
  readonly encryptedRecord: EncryptedRecordValue | null;
  readonly deleted: boolean;
}

export interface SyncRecordItem {
  readonly pk: string;
  readonly sk: string;
  readonly record_id: string;
  readonly revision: bigint;
  readonly server_sequence: bigint;
  readonly deleted: boolean;
  readonly encrypted_record?: EncryptedRecordValue;
}

export interface RevisionCondition {
  readonly ConditionExpression: string;
  readonly ExpressionAttributeNames: Readonly<Record<string, string>>;
  readonly ExpressionAttributeValues?: Readonly<Record<string, bigint>>;
}

export function revisionCondition(expectedRevision: bigint | null): RevisionCondition {
  if (expectedRevision === null) {
    return {
      ConditionExpression: "attribute_not_exists(#pk)",
      ExpressionAttributeNames: { "#pk": "pk" }
    };
  }
  if (expectedRevision < 1n) {
    throw new Error("expected revision must be positive");
  }
  return {
    ConditionExpression: "#revision = :expected_revision",
    ExpressionAttributeNames: { "#revision": "revision" },
    ExpressionAttributeValues: { ":expected_revision": expectedRevision }
  };
}

function opaqueKey(prefix: "USER" | "RECORD", value: string): string {
  if (!UUID_PATTERN.test(value)) {
    throw new Error(`${prefix === "USER" ? "owner" : "record"} ID must be a UUID`);
  }
  return `${prefix}#${value.toLowerCase()}`;
}

export function toSyncRecordItem(ownerId: string, record: SyncRecordValue): SyncRecordItem {
  if (record.revision < 1n || record.serverSequence < 1n) {
    throw new Error("sync revision and sequence must be positive");
  }
  if (record.deleted !== (record.encryptedRecord === null)) {
    throw new Error("tombstones must omit encrypted record data");
  }

  const item: SyncRecordItem = {
    pk: opaqueKey("USER", ownerId),
    sk: opaqueKey("RECORD", record.recordId),
    record_id: record.recordId.toLowerCase(),
    revision: record.revision,
    server_sequence: record.serverSequence,
    deleted: record.deleted
  };
  if (record.encryptedRecord === null) {
    return item;
  }

  return {
    ...item,
    encrypted_record: {
      ciphertext: record.encryptedRecord.ciphertext,
      wrappedRecordKey: record.encryptedRecord.wrappedRecordKey,
      nonce: record.encryptedRecord.nonce,
      keyWrappingNonce: record.encryptedRecord.keyWrappingNonce,
      cryptoVersion: record.encryptedRecord.cryptoVersion
    }
  };
}
