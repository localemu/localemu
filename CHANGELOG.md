# Changelog

## 1.1.0

Correctness and coverage release. IAM enforcement now respects attached
managed policies and resource-based policies, the operation → IAM action
map matches AWS for Lambda, S3 multipart, and several rewritten
bucket-config actions, IMDS at 169.254.169.254 is reachable inside
containers launched without a key pair, multi-account is documented and
surfaced with AWS Organizations support, S3 replicates objects on every
matching rule, and a class of EC2 / SSM / Backup operations that
previously raised `InternalFailure` now return AWS-shaped responses.

### IAM enforcement: managed policies, permission boundaries, and resource-based policies

`IAM_ENFORCEMENT=1` now evaluates attached managed policies on every
attachment surface (user, role, group-via-user) and applies managed
permission boundaries by intersection with the identity grant. The
previous release's gather step silently dropped every managed-policy
document (read the wrong attribute on moto's `ManagedPolicy`) and the
boundary path silently ignored a managed-ARN boundary (read a
property-derived dict instead of the underlying ARN string), producing
two opposing failure modes: false `AccessDenied` on legitimate managed
grants, and silently over-permissive evaluation when a boundary should
have intersected.

For cross-account requests, the resource-based policy evaluator now
loads the target service's resource policy (S3 bucket policy, KMS key
policy, SQS / SNS / Lambda / EventBridge policies) and evaluates it
against the caller. Six new condition keys are populated:
`aws:PrincipalAccount`, `aws:ResourceAccount`, `aws:SourceAccount`,
`aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:ResourceOrgID`.

### Operation → IAM action map

Added the Lambda, S3-multipart, S3 bucket-config, SQS / SNS batch, KMS
`ReEncrypt`, DynamoDB transaction, and S3Control access-point rows to
`iam_enforcement.service_action_map.ACTION_MAP`. The most-visible fixes:

- `lambda:Invoke` (the wire op) maps to `lambda:InvokeFunction` (the
  documented IAM action), so policies written the real-AWS way stop
  returning `AccessDenied`.
- S3Control access-point operations (`CreateAccessPoint`,
  `GetAccessPoint`, `PutAccessPointPolicy`, …) authorize against the
  AWS-correct `s3:` namespace, not the wire `s3control:` prefix.

### IMDS at 169.254.169.254 on no-key instances

The iptables DNAT redirect that wires `169.254.169.254 -> sidecar` is
now installed regardless of `--key-name`. Previously it lived inside
`SSHD_ENTRYPOINT_SCRIPT` and only ran when an instance was launched
with a key; the AWS CLI default (no key) skipped the script and the
canonical IMDS address returned `Connection refused`. A new
`NO_SSH_ENTRYPOINT_SCRIPT` carries the same DNAT install and a
`docker logs` line surfaces the outcome.

### S3 replication data plane

`PutObject` / `CompleteMultipartUpload` / `CopyObject` on a bucket with
a `ReplicationConfiguration` now asynchronously copies every matching
object version to each `Destination`. Source object flips
`ReplicationStatus` from `PENDING` to `COMPLETED` (or `FAILED`);
destination object carries `REPLICA`; `VersionId`, metadata, tags, and
content-type are preserved. Filter forms (empty, `Prefix`, `Tag`,
`And{Prefix?, Tag+}`) are honored, priority resolution per destination
works, `DeleteMarkerReplication` is gated correctly (tag-rule and
lifecycle exclusions per AWS docs), GLACIER-class source objects are
skipped, and replicas of replicas are blocked. Cross-account
destinations route through the central account registry and consult the
destination bucket policy.

### Multi-account and AWS Organizations

The multi-account namespacing already inherited from upstream is now
documented and surfaced:

- A central account registry (`localemu.accounts.registry`) auto-populates
  every 12-digit access key the gateway sees, and is queryable via
  `GET /_localemu/api/accounts`. Explicit accounts can be created via
  `POST /_localemu/api/accounts` and removed via `DELETE`.
- The AWS Organizations service is wired with the full 39 ops. The
  previously-unimplemented `DescribeEffectivePolicy` returns an
  AWS-shaped empty document.
- `Organizations.CreateAccount` auto-seeds an `OrganizationAccountAccessRole`
  in the new member with the AWS-standard trust policy pointing at the
  management account, plus an inline `AdministratorAccess` policy so an
  immediate `sts:AssumeRole` from the management account works the way
  AWS does it.

### S3 Access Point data plane

Object operations (`GetObject`, `PutObject`, `DeleteObject`, `HeadObject`,
`ListObjectsV2`, `CopyObject`, the multipart suite) addressed to an
access point — by ARN, alias (`<name>-<34hex>-s3alias`), or hostname
(`<name>-<account>.s3-accesspoint.<region>.amazonaws.com`) — are routed
to the underlying bucket, scoped by the access point. Under
`IAM_ENFORCEMENT=1`, the AP policy is evaluated alongside the bucket
policy and three S3 condition keys are populated for AP requests:
`s3:DataAccessPointArn`, `s3:DataAccessPointAccount`,
`s3:AccessPointNetworkOrigin`. Bucket-policy delegation via
`s3:DataAccessPointAccount` works the AWS way: a low-privilege
principal denied direct bucket access is allowed when the request
arrives through an access point in the trusted account.

AP-incompatible operations (bucket lifecycle, replication, versioning,
encryption, etc.) called against an AP ARN return `InvalidRequest`
matching the AWS message. VPC-restricted access points enforce the
network origin via the `x-localemu-from-vpc-id` header.

### Security-scanner coverage: typed responses for previously-unimplemented EC2 / SSM / Backup operations

Six previously-`InternalFailure` operations now return AWS-correct
shapes:

- EC2 `GetSnapshotBlockPublicAccessState` / `Enable*` / `Disable*` with
  full state machine and persisted account-region state. The companion
  `ModifySnapshotAttribute` override blocks public-share requests when
  Snapshot BPA is enabled (`OperationNotPermitted`).
- EC2 `GetSerialConsoleAccessStatus` / `Enable*` / `Disable*`.
- EC2 `DescribeVpcBlockPublicAccessOptions` / `Modify*` plus the four
  `*VpcBlockPublicAccessExclusion` ops (state machine, filters, tag
  passthrough, quota of 50 per region). Data-plane enforcement: the
  entrypoint scripts install dedicated `LOCALEMU_VPC_BPA_IN` /
  `LOCALEMU_VPC_BPA_OUT` iptables chains on the IGW-facing interface
  when the mode is `block-ingress` or `block-bidirectional` and the
  instance's subnet or VPC has no active exclusion.
- EC2 `CreateInstanceConnectEndpoint` / `Describe*` / `Delete*`
  (metadata-only: terminal state is `create-complete`, ENI synthesis
  is tracked for a follow-up release).
- AWS Backup `DescribeProtectedResource` / `ListProtectedResources` /
  `CreateBackupSelection`. Moto already implements `CreateBackupPlan`
  and `CreateBackupVault`; we add the missing URL routes and handler
  methods on the existing `BackupResponse`, plus a small native store
  for selections and a lazy protected-resource index.
- SSM `DescribeInstancePatchStates` /
  `DescribeInstancePatchStatesForPatchGroup` / `GetPatchBaseline`.
  Real AWS silently drops unknown instance IDs on the first two, so
  the AWS-correct default is `{InstancePatchStates: []}`.

### Numbers

| | 1.0.0 | 1.1.0 |
|---|---|---|
| EC2 service handlers | (baseline) | + 16 (Snapshot BPA ×3, Serial Console ×3, VPC BPA options ×2, VPC BPA exclusions ×4, EICE ×3, `ModifySnapshotAttribute` gate) |
| SSM service handlers | (baseline) | + 3 (patch reads) |
| Backup URL routes | 6 | 10 |
| S3 access-point routing forms | 0 | 3 (ARN, alias, hostname) |
| Resource policy evaluators | 4 (S3, SQS, SNS, KMS) | 6 (+ Lambda, EventBridge) |
| Organizations ops surfaced | 0 | 39 |
| Admin endpoints | 0 | 4 (accounts list / create / delete / summary) |
| New condition keys | 0 | 9 (6 org/account scoping + 3 access-point) |
| New unit tests | - | 200+ |
| New E2E tests | - | 59 |

### Migration notes

- A workload that was passing tests against LocalEmu while granting the
  non-AWS-standard `lambda:Invoke` permission stops working: switch the
  policy to `lambda:InvokeFunction` (the real AWS action).
- A workload that was silently relying on a managed permission boundary
  having no observable effect now sees the boundary intersected.
- A workload granting `s3control:CreateAccessPoint` and similar
  non-existent IAM actions stops working: switch to `s3:CreateAccessPoint`
  (the real AWS action).
- `ModifyVpcBlockPublicAccessOptions` changes apply to NEW instances
  immediately; instances already running pick up the new mode on
  restart. AWS propagates within seconds; we do not model that latency.
- S3 replication does NOT replicate objects that existed before the
  rule was added. That is `S3 Batch Replication` on real AWS and is
  out of scope here.

### Credits

The IAM enforcement and security-scanner coverage gaps were reported
and reproduced by Tarek using his own EC2 security scanner against
LocalEmu 1.0.0. The S3 replication and S3 Access Point data planes
were prioritized to unblock the matching attack labs in the
aws-scanners-articles project.
