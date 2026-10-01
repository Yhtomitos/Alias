import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { GetCommand, PutCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

import {
  fromSyncRecordItem,
  ownerKey,
  recordKey,
  revisionCondition,
  toSyncRecordItem,
  type EncryptedRecordValue,
  type SyncRecordValue
} from "./sync-item.js";

export interface DynamoCommandClient {
  send(command: GetCommand | PutCommand | UpdateCommand): Promise<unknown>;
}

export class SyncConflictError extends Error {}

export type SyncMutationValue =
  | {
      readonly operation: "upsert";
      readonly expectedRevision: bigint | null;
      readonly encryptedRecord: EncryptedRecordValue;
    }
  | { readonly operation: "delete"; readonly expectedRevision: bigint };

export class DynamoSyncStore {
  public constructor(
    private readonly client: DynamoCommandClient,
    private readonly tableName: string
  ) {}

  public async nextSequence(ownerId: string): Promise<bigint> {
    const result = (await this.client.send(
      new UpdateCommand({
        TableName: this.tableName,
        Key: { pk: ownerKey(ownerId), sk: "META#SYNC" },
        UpdateExpression: "ADD #server_sequence :one",
        ExpressionAttributeNames: { "#server_sequence": "server_sequence" },
        ExpressionAttributeValues: { ":one": 1n },
        ReturnValues: "UPDATED_NEW"
      })
    )) as { Attributes?: Record<string, unknown> };
    const sequence = result.Attributes?.server_sequence;

    if (typeof sequence === "bigint" && sequence > 0n) {
      return sequence;
    }
    if (typeof sequence === "number" && Number.isSafeInteger(sequence) && sequence > 0) {
      return BigInt(sequence);
    }
    throw new Error("DynamoDB returned an invalid server sequence");
  }

  public async applyMutation(
    ownerId: string,
    recordId: string,
    mutation: SyncMutationValue
  ): Promise<SyncRecordValue> {
    recordKey(recordId);
    revisionCondition(mutation.expectedRevision);
    const serverSequence = await this.nextSequence(ownerId);
    const record: SyncRecordValue = {
      recordId,
      revision: mutation.expectedRevision === null ? 1n : mutation.expectedRevision + 1n,
      serverSequence,
      encryptedRecord: mutation.operation === "upsert" ? mutation.encryptedRecord : null,
      deleted: mutation.operation === "delete"
    };

    await this.put(ownerId, record, mutation.expectedRevision);
    return record;
  }

  public async currentRecord(ownerId: string, recordId: string): Promise<SyncRecordValue | null> {
    const result = (await this.client.send(
      new GetCommand({
        TableName: this.tableName,
        Key: { pk: ownerKey(ownerId), sk: recordKey(recordId) },
        ConsistentRead: true
      })
    )) as { Item?: unknown };

    return result.Item === undefined ? null : fromSyncRecordItem(ownerId, recordId, result.Item);
  }

  public async put(
    ownerId: string,
    record: SyncRecordValue,
    expectedRevision: bigint | null
  ): Promise<void> {
    const nextRevision = expectedRevision === null ? 1n : expectedRevision + 1n;
    if (record.revision !== nextRevision) {
      throw new Error("record revision must immediately follow expected revision");
    }

    const command = new PutCommand({
      TableName: this.tableName,
      Item: toSyncRecordItem(ownerId, record),
      ...revisionCondition(expectedRevision)
    });
    try {
      await this.client.send(command);
    } catch (error: unknown) {
      if (error instanceof ConditionalCheckFailedException) {
        throw new SyncConflictError("sync revision conflict", { cause: error });
      }
      throw error;
    }
  }
}
