# Rule mapping

Generated from the vendored AWS Solutions inventory.

| Rule | Level | Status | CloudFormation origin | Terraform coverage |
|---|---|---|---|---|
| `AwsSolutions-AEC1` | ERROR | implemented | CacheCluster, ReplicationGroup | Implemented by tf-nag rules. |
| `AwsSolutions-AEC3` | ERROR | implemented | ReplicationGroup | Implemented by tf-nag rules. |
| `AwsSolutions-AEC4` | ERROR | implemented | ReplicationGroup | Implemented by tf-nag rules. |
| `AwsSolutions-AEC5` | ERROR | implemented | CacheCluster, ReplicationGroup | Implemented by tf-nag rules. |
| `AwsSolutions-AEC6` | ERROR | implemented | ReplicationGroup | Implemented by tf-nag rules. |
| `AwsSolutions-APIG1` | ERROR | implemented | Stage, V2Stage | Implemented by tf-nag rules. |
| `AwsSolutions-APIG2` | ERROR | implemented | RequestValidator, RestApi | Implemented by tf-nag rules. |
| `AwsSolutions-APIG3` | WARN | implemented | Stage, WebACLAssociation | Implemented by tf-nag rules. |
| `AwsSolutions-APIG4` | ERROR | implemented | Method, Route | Implemented by tf-nag rules. |
| `AwsSolutions-APIG6` | ERROR | implemented | Stage | Implemented by tf-nag rules. |
| `AwsSolutions-AS1` | ERROR | implemented | AutoScalingGroup | Implemented by tf-nag rules. |
| `AwsSolutions-AS2` | ERROR | implemented | AutoScalingGroup | Implemented by tf-nag rules. |
| `AwsSolutions-AS3` | ERROR | implemented | AutoScalingGroup | Implemented by tf-nag rules. |
| `AwsSolutions-ASC3` | ERROR | implemented | GraphQLApi | Implemented by tf-nag rules. |
| `AwsSolutions-C91` | ERROR | implemented | EnvironmentEC2 | Implemented by tf-nag rules. |
| `AwsSolutions-CB4` | ERROR | implemented | Project | Implemented by tf-nag rules. |
| `AwsSolutions-CB5` | WARN | implemented | Project | Implemented by tf-nag rules. |
| `AwsSolutions-CFR1` | WARN | implemented | Distribution | Implemented by tf-nag rules. |
| `AwsSolutions-CFR2` | WARN | implemented | Distribution | Implemented by tf-nag rules. |
| `AwsSolutions-CFR3` | ERROR | implemented | Distribution, StreamingDistribution | Implemented by tf-nag rules. |
| `AwsSolutions-CFR4` | ERROR | implemented | Distribution | Implemented by tf-nag rules. |
| `AwsSolutions-CFR5` | ERROR | implemented | Distribution | Implemented by tf-nag rules. |
| `AwsSolutions-CFR6` | ERROR | not-applicable-to-terraform | StreamingDistribution | Terraform AWS provider has no CloudFront streaming-distribution resource. |
| `AwsSolutions-CFR7` | ERROR | implemented | Bucket, Distribution | Implemented by tf-nag rules. |
| `AwsSolutions-COG1` | ERROR | implemented | UserPool | Implemented by tf-nag rules. |
| `AwsSolutions-COG2` | WARN | implemented | UserPool | Implemented by tf-nag rules. |
| `AwsSolutions-COG4` | ERROR | implemented | Method | Implemented by tf-nag rules. |
| `AwsSolutions-COG7` | ERROR | implemented | IdentityPool | Implemented by tf-nag rules. |
| `AwsSolutions-COG8` | ERROR | implemented | UserPool | Implemented by tf-nag rules. |
| `AwsSolutions-DDB3` | WARN | implemented | Table | Implemented by tf-nag rules. |
| `AwsSolutions-DDB4` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-DOC1` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-DOC2` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-DOC3` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-DOC4` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-DOC5` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-EB1` | ERROR | implemented | Environment | Implemented by tf-nag rules. |
| `AwsSolutions-EB3` | ERROR | implemented | Environment | Implemented by tf-nag rules. |
| `AwsSolutions-EB4` | WARN | implemented | Environment | Implemented by tf-nag rules. |
| `AwsSolutions-EC23` | ERROR | implemented | SecurityGroup, SecurityGroupIngress | Implemented by tf-nag rules. |
| `AwsSolutions-EC26` | ERROR | implemented | AutoScalingGroup, Instance, LaunchConfiguration, LaunchTemplate, Volume | Implemented by tf-nag rules. |
| `AwsSolutions-EC27` | ERROR | implemented | SecurityGroup | Implemented by tf-nag rules. |
| `AwsSolutions-EC28` | ERROR | implemented | Instance, LaunchConfiguration | Implemented by tf-nag rules. |
| `AwsSolutions-EC29` | ERROR | implemented | Instance | Implemented by tf-nag rules. |
| `AwsSolutions-ECR1` | ERROR | implemented | RegistryPolicy, Repository | Implemented by tf-nag rules. |
| `AwsSolutions-ECS2` | ERROR | implemented | TaskDefinition | Implemented by tf-nag rules. |
| `AwsSolutions-ECS4` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-ECS7` | ERROR | implemented | TaskDefinition | Implemented by tf-nag rules. |
| `AwsSolutions-EFS1` | ERROR | implemented | FileSystem | Implemented by tf-nag rules. |
| `AwsSolutions-EKS1` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-EKS2` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-ELB1` | ERROR | implemented | LoadBalancer | Implemented by tf-nag rules. |
| `AwsSolutions-ELB2` | ERROR | implemented | LoadBalancer, LoadBalancerV2 | Implemented by tf-nag rules. |
| `AwsSolutions-ELB3` | ERROR | implemented | LoadBalancer | Implemented by tf-nag rules. |
| `AwsSolutions-ELB4` | ERROR | implemented | LoadBalancer | Implemented by tf-nag rules. |
| `AwsSolutions-ELB5` | ERROR | implemented | LoadBalancer | Implemented by tf-nag rules. |
| `AwsSolutions-EMR2` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-EMR4` | ERROR | implemented | Cluster, SecurityConfiguration | Implemented by tf-nag rules. |
| `AwsSolutions-EMR5` | ERROR | implemented | Cluster, SecurityConfiguration | Implemented by tf-nag rules. |
| `AwsSolutions-EMR6` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-EVB1` | ERROR | implemented | EventBusPolicy | Implemented by tf-nag rules. |
| `AwsSolutions-GL1` | WARN | implemented | Crawler, Job, SecurityConfiguration | Implemented by tf-nag rules. |
| `AwsSolutions-GL3` | WARN | implemented | Job, SecurityConfiguration | Implemented by tf-nag rules. |
| `AwsSolutions-IAM4` | ERROR | implemented | Group, Role, User | Implemented by tf-nag rules. |
| `AwsSolutions-IAM5` | ERROR | implemented | Group, ManagedPolicy, Policy, Role, User | Implemented by tf-nag rules. |
| `AwsSolutions-KDA3` | WARN | implemented | ApplicationV2 | Implemented by tf-nag rules. |
| `AwsSolutions-KDF1` | ERROR | implemented | DeliveryStream | Implemented by tf-nag rules. |
| `AwsSolutions-KDS1` | ERROR | implemented | Stream | Implemented by tf-nag rules. |
| `AwsSolutions-KDS3` | WARN | implemented | Stream | Implemented by tf-nag rules. |
| `AwsSolutions-KMS5` | ERROR | implemented | Key | Implemented by tf-nag rules. |
| `AwsSolutions-L1` | ERROR | implemented | Function | Implemented by tf-nag rules. |
| `AwsSolutions-LEX4` | ERROR | implemented | Bot, BotAlias, LogGroup | Implemented by tf-nag rules. |
| `AwsSolutions-MS1` | ERROR | not-applicable-to-terraform | Container | Terraform AWS provider exposes no MediaStore access-logging configuration. |
| `AwsSolutions-MS10` | WARN | not-applicable-to-terraform | Container | Terraform AWS provider exposes no MediaStore lifecycle-policy resource. |
| `AwsSolutions-MS3` | ERROR | implemented | Container | Implemented by tf-nag rules. |
| `AwsSolutions-MS4` | WARN | not-applicable-to-terraform | Container | Terraform AWS provider exposes no MediaStore CloudWatch metric-policy resource. |
| `AwsSolutions-MS7` | WARN | implemented | Container | Implemented by tf-nag rules. |
| `AwsSolutions-MS8` | WARN | not-applicable-to-terraform | Container | Terraform AWS provider exposes no MediaStore CORS-policy resource. |
| `AwsSolutions-MSK2` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-MSK3` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-MSK6` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-N1` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-N2` | ERROR | implemented | DBInstance | Implemented by tf-nag rules. |
| `AwsSolutions-N3` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-N4` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-N5` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-OS1` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-OS2` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-OS3` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-OS4` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-OS5` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-OS7` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-OS8` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-OS9` | ERROR | implemented | Domain | Implemented by tf-nag rules. |
| `AwsSolutions-QS1` | ERROR | implemented | DataSource | Implemented by tf-nag rules. |
| `AwsSolutions-RDS10` | ERROR | implemented | DBCluster, DBInstance | Implemented by tf-nag rules. |
| `AwsSolutions-RDS11` | ERROR | implemented | DBCluster, DBInstance | Implemented by tf-nag rules. |
| `AwsSolutions-RDS13` | ERROR | implemented | DBInstance | Implemented by tf-nag rules. |
| `AwsSolutions-RDS14` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-RDS16` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-RDS2` | ERROR | implemented | DBCluster, DBInstance | Implemented by tf-nag rules. |
| `AwsSolutions-RDS3` | ERROR | implemented | DBInstance | Implemented by tf-nag rules. |
| `AwsSolutions-RDS6` | ERROR | implemented | DBCluster | Implemented by tf-nag rules. |
| `AwsSolutions-RDS8` | ERROR | implemented | DBSecurityGroup, DBSecurityGroupIngress | Implemented by tf-nag rules. |
| `AwsSolutions-RS1` | ERROR | implemented | Cluster, ClusterParameterGroup | Implemented by tf-nag rules. |
| `AwsSolutions-RS10` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-RS11` | ERROR | implemented | Cluster, ClusterParameterGroup | Implemented by tf-nag rules. |
| `AwsSolutions-RS2` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-RS3` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-RS4` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-RS5` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-RS6` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-RS8` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-RS9` | ERROR | implemented | Cluster | Implemented by tf-nag rules. |
| `AwsSolutions-S1` | ERROR | implemented | Bucket | Implemented by tf-nag rules. |
| `AwsSolutions-S10` | ERROR | implemented | Bucket, BucketPolicy | Implemented by tf-nag rules. |
| `AwsSolutions-S2` | ERROR | implemented | Bucket | Implemented by tf-nag rules. |
| `AwsSolutions-S5` | ERROR | implemented | Bucket, BucketPolicy | Implemented by tf-nag rules. |
| `AwsSolutions-SF1` | ERROR | implemented | StateMachine | Implemented by tf-nag rules. |
| `AwsSolutions-SF2` | ERROR | implemented | StateMachine | Implemented by tf-nag rules. |
| `AwsSolutions-SM1` | ERROR | implemented | NotebookInstance | Implemented by tf-nag rules. |
| `AwsSolutions-SM2` | ERROR | implemented | NotebookInstance | Implemented by tf-nag rules. |
| `AwsSolutions-SM3` | ERROR | implemented | NotebookInstance | Implemented by tf-nag rules. |
| `AwsSolutions-SMG4` | ERROR | implemented | RotationSchedule, Secret, SecretTargetAttachment, TargetAttachment | Implemented by tf-nag rules. |
| `AwsSolutions-SNS3` | ERROR | implemented | Topic, TopicPolicy | Implemented by tf-nag rules. |
| `AwsSolutions-SQS2` | ERROR | implemented | Queue | Implemented by tf-nag rules. |
| `AwsSolutions-SQS3` | ERROR | implemented | Function, Queue | Implemented by tf-nag rules. |
| `AwsSolutions-SQS4` | ERROR | implemented | Queue, QueuePolicy | Implemented by tf-nag rules. |
| `AwsSolutions-TS3` | WARN | implemented | Database | Implemented by tf-nag rules. |
| `AwsSolutions-VPC3` | WARN | implemented | NetworkAcl, NetworkAclEntry | Implemented by tf-nag rules. |
| `AwsSolutions-VPC7` | ERROR | implemented | FlowLog, VPC | Implemented by tf-nag rules. |
