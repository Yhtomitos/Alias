import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { PutCommand, UpdateCommand } from "@aws-sdk/lib-dynamodb";

import {
  ownerKey,
  revisionCondition,
  toSyncRecordItem,
  type SyncRecordValue
} from "./sync-item.js";

export interface DynamoCommandClient {
  send(command: PutCommand | UpdateCommand): Promise<unknown>;
}

export class SyncConflictError extends Error {}

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
