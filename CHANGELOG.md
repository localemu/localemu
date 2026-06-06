# Changelog

## 1.1.0

Correctness and coverage release. Closes BUG-001, BUG-002, BUG-003, BUG-004.

### IAM enforcement (BUG-001)

`IAM_ENFORCEMENT=1` now evaluates attached managed policies on every
attachment surface (user, role, group-via-user) and applies managed
permission boundaries by intersection with the identity grant. Before
this release the gather step silently dropped every managed-policy
document (read the wrong attribute on moto's `ManagedPolicy`) and the
boundary path silently ignored a managed-ARN boundary (read a
property-derived dict instead of the underlying ARN string), producing
two opposing failure modes: false `AccessDenied` on legitimate managed
grants, and silently over-permissive evaluation when a boundary should
have intersected.

### Operation -> IAM action map (BUG-002)

Added the Lambda, S3-multipart, S3 bucket-config, SQS/SNS batch, KMS
`ReEncrypt`, and DynamoDB transaction rows to
`iam_enforcement.service_action_map.ACTION_MAP`. The most-visible fix:
`lambda:Invoke` (the wire op name) now correctly maps to
`lambda:InvokeFunction` (the documented IAM action), so policies written
the real-AWS way stop returning `AccessDenied`.

### IMDS link-local DNAT (BUG-003)

The iptables DNAT redirect that wires `169.254.169.254 -> sidecar` is
now installed regardless of `--key-name`. Previously it lived inside
`SSHD_ENTRYPOINT_SCRIPT` and only ran when an instance was launched
with a key; the AWS CLI default (no key) skipped the script and the
canonical IMDS address returned `Connection refused`. A new
`NO_SSH_ENTRYPOINT_SCRIPT` carries the same DNAT install and a
`docker logs` line surfaces the outcome.

### Security-scanner coverage (BUG-004 + the 1.1.0 design)

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
  is tracked for 1.2).
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
| EC2 service handlers | (baseline) | + 16 (Snapshot BPA x3, Serial Console x3, VPC BPA options x2, VPC BPA exclusions x4, EICE x3, `ModifySnapshotAttribute` gate) |
| SSM service handlers | (baseline) | + 3 (patch reads) |
| Backup URL routes | 6 | 10 |
| New unit tests | - | 123 |

### Migration notes

- A workload that was passing tests against LocalEmu while granting the
  non-AWS-standard `lambda:Invoke` permission stops working: switch the
  policy to `lambda:InvokeFunction` (the real AWS action).
- A workload that was silently relying on a managed permission boundary
  having no observable effect now sees the boundary intersected.
- `ModifyVpcBlockPublicAccessOptions` changes apply to NEW instances
  immediately; instances already running pick up the new mode on
  restart. AWS propagates within seconds; we do not model that latency.

### Credits

BUG-001, BUG-002, BUG-003, and BUG-004 were all reported and
reproduced by Tarek using his own EC2 security scanner against
LocalEmu 1.0.0.
