import { Stack, type StackProps } from "aws-cdk-lib";
import type { Construct } from "constructs";

export interface AliasStackProps extends StackProps {
  readonly stage: string;
}

export class AliasStack extends Stack {
  public constructor(scope: Construct, id: string, props: AliasStackProps) {
    const { stage, ...stackProps } = props;
    if (!/^[a-z][a-z0-9-]{1,19}$/.test(stage)) {
      throw new Error("stage must be 2-20 lowercase letters, numbers, or hyphens");
    }

    super(scope, id, {
      description: `Alias encrypted synchronization (${stage})`,
      ...stackProps
    });

    this.tags.setTag("alias:stage", stage);
  }
}
