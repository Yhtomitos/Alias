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

export function ownerKey(ownerId: string): string {
  return opaqueKey("USER", ownerId);
}

export function recordKey(recordId: string): string {
  return opaqueKey("RECORD", recordId);
}

function malformedItem(): never {
  throw new Error("DynamoDB returned a malformed sync record");
}

function positiveInteger(value: unknown): bigint {
  if (typeof value === "bigint" && value > 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return BigInt(value);
  }
  return malformedItem();
}

export function fromSyncRecordItem(
  ownerId: string,
  recordId: string,
  value: unknown
): SyncRecordValue {
  if (typeof value !== "object" || value === null) return malformedItem();
  const item = value as Record<string, unknown>;
  if (
    item.pk !== ownerKey(ownerId) ||
    item.sk !== recordKey(recordId) ||
    item.record_id !== recordId.toLowerCase() ||
    typeof item.deleted !== "boolean"
  ) {
    return malformedItem();
  }

  const encrypted = item.encrypted_record;
  if (item.deleted) {
    if (encrypted !== undefined) return malformedItem();
    return {
      recordId: recordId.toLowerCase(),
      revision: positiveInteger(item.revision),
      serverSequence: positiveInteger(item.server_sequence),
      encryptedRecord: null,
      deleted: true
    };
  }
  if (typeof encrypted !== "object" || encrypted === null) return malformedItem();
  const fields = encrypted as Record<string, unknown>;
  if (
    !(fields.ciphertext instanceof Uint8Array) ||
    !(fields.wrappedRecordKey instanceof Uint8Array) ||
    !(fields.nonce instanceof Uint8Array) ||
    fields.nonce.length !== 24 ||
    !(fields.keyWrappingNonce instanceof Uint8Array) ||
    fields.keyWrappingNonce.length !== 24 ||
    typeof fields.cryptoVersion !== "number" ||
    !Number.isInteger(fields.cryptoVersion) ||
    fields.cryptoVersion < 0 ||
    fields.cryptoVersion > 255
  ) {
    return malformedItem();
  }
  return {
    recordId: recordId.toLowerCase(),
    revision: positiveInteger(item.revision),
    serverSequence: positiveInteger(item.server_sequence),
    encryptedRecord: {
      ciphertext: fields.ciphertext,
      wrappedRecordKey: fields.wrappedRecordKey,
      nonce: fields.nonce,
      keyWrappingNonce: fields.keyWrappingNonce,
      cryptoVersion: fields.cryptoVersion
    },
    deleted: false
  };
}

export function toSyncRecordItem(ownerId: string, record: SyncRecordValue): SyncRecordItem {
  if (record.revision < 1n || record.serverSequence < 1n) {
    throw new Error("sync revision and sequence must be positive");
  }
  if (record.deleted !== (record.encryptedRecord === null)) {
    throw new Error("tombstones must omit encrypted record data");
  }

  const item: SyncRecordItem = {
    pk: ownerKey(ownerId),
    sk: recordKey(record.recordId),
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
