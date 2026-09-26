import { ConditionalCheckFailedException } from "@aws-sdk/client-dynamodb";
import { PutCommand } from "@aws-sdk/lib-dynamodb";

import { revisionCondition, toSyncRecordItem, type SyncRecordValue } from "./sync-item.js";

export interface DynamoCommandClient {
  send(command: PutCommand): Promise<unknown>;
}

export class SyncConflictError extends Error {}

export class DynamoSyncStore {
  public constructor(
    private readonly client: DynamoCommandClient,
    private readonly tableName: string
  ) {}

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
