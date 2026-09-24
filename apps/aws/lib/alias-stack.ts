import { Stack, type StackProps } from "aws-cdk-lib";
import type { Construct } from "constructs";

export interface AliasStackProps extends StackProps {
  readonly stage: string;
}

export class AliasStack extends Stack {
  public constructor(scope: Construct, id: string, props: AliasStackProps) {
    super(scope, id, props);

    this.tags.setTag("alias:stage", props.stage);
  }
}
