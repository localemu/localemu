# Changelog

## 1.2.0

EC2 access end-to-end (SSM shell, SSH, EC2 Instance Connect, SSM port-forwarding), snapshot honesty, ENI-level live security-group re-apply, EC2 multi-NIC, Cognito User Pool Lambda triggers, and a full excision of every external URL from the code base.

### EC2 SSM Session Manager, real interactive shell

The wire codec now matches the real `session-manager-plugin` byte-for-byte : `HeaderLength = 116` on the wire, total header = 120 bytes, message-type field stripped of both null and space padding. The WebSocket authentication step responds to the plugin's `StartPings` control frame with a proper `Pong` (`wsproto` does not auto-Pong). Sequence numbering separates strictly monotonic `output_stream_data` from `acknowledge` frames (which must always be `seq=0`, dispatched by `MessageId`). `aws ssm start-session --target i-...` opens a proper bash prompt against the target container, runs commands, and closes cleanly on `exit`.

### EC2 base image v4 : `ubuntu` user, per-AMI canonical user

`localemu/ec2-base:v4` adds an `ubuntu` user (uid 1000, sudo NOPASSWD) alongside the existing `root`. A per-AMI canonical-user table maps AMI id → default OS user (`ubuntu` for Ubuntu, `ec2-user` for Amazon Linux, `admin` for Debian, `alpine` for Alpine, `cloud-user` for RHEL), and `--key-name` injection writes the authorized_keys entry to both `/home/<user>/.ssh/authorized_keys` and `/root/.ssh/authorized_keys`. `ssh ubuntu@<PrivateIpAddress>` works and `sudo -n whoami` returns `root`, matching real EC2.

### EC2 Instance Connect

`SendSSHPublicKey` writes the ephemeral public key into a marker-wrapped block in the target user's `authorized_keys` and schedules a `threading.Timer(60, cleanup)` to remove it after the AWS-defined 60-second TTL. `SendSerialConsoleSSHPublicKey` returns the AWS-shaped `SerialConsoleAccessDisabledException`. `ssh -i <eic-key> ubuntu@<PrivateIp>` succeeds within 60 s, fails after.

### EC2 SSM AWS-StartPortForwardingSession, SMUX v1 for real

The AWS `session-manager-plugin` uses **xtaci/smux v1** framing to multiplex user connections over the WebSocket data channel whenever the target agent version is above 3.0.196.0. A pure-Python codec (`services/ssm/smux_v1.py`, byte-verified against xtaci/smux's `frame.go`) plus a per-`sid` mux bridge (`services/ssm/port_mux_bridge.py`) speak the same wire : per accepted SMUX stream, `docker exec -i <container> nc 127.0.0.1 <targetPort>` opens the tunnel, PSH frames are forwarded both directions, FIN half-closes cleanly. `aws ssm start-session --document-name AWS-StartPortForwardingSession --parameters portNumber=8012,localPortNumber=18012` + `curl http://127.0.0.1:18012/` returns the target's HTTP body via real AWS tooling. Reproducible across back-to-back runs.

A dispatched wire bug in the plugin itself : its `MuxPortForwarding.SetOnMessage` handler dereferences `p.muxClient.conn` before `p.muxClient` is assigned in `initialize()`. Any WebSocket message received during that race window panics the plugin's WS receive goroutine, which then silently exits. LocalEmu now skips ACKing incoming `acknowledge` frames (matching real amazon-ssm-agent behaviour, ACKs are fire-and-forget on both ends), so no ACK-of-ACK ever hits the plugin's race window. Fix applied symmetrically in both the shell (`_bridge_shell`) and port (`_bridge_port`) paths.

### EC2 PublicIpAddress honesty

`DescribeInstances` used to fall back to `127.0.0.1` and stamp a `localemu:ssh-port` tag when it could not resolve a real address, and moto's random `54.214.x.x` value leaked through in unrelated code paths. Now `PublicIpAddress` is either a genuine host-side IP on the `localemu-pubport-br` bridge (or the EIP association, if any) or absent. `PublicDnsName` is AWS-shape `ec2-<ip-dashed>.compute-1.amazonaws.com` when set, absent otherwise. IMDS (`/latest/meta-data/public-ipv4`, `/public-hostname`) agrees with the API. The `localemu:ssh-port` tag is gone.

### EC2 DescribeSnapshots honours `OwnerIds`, DescribePlacementGroups implemented

The pass-through to moto silently dropped the `OwnerIds` request parameter, so `describe_snapshots(OwnerIds=['<account>'])` returned all 1177 seeded-AMI backing snapshots instead of the caller's zero. A `@patch` on `ElasticBlockStoreResponse.describe_snapshots` in `services/ec2/patches.py` now filters correctly : `OwnerIds=['self']` resolves to the caller account, `OwnerIds=['amazon']` matches the AMI's `owner_alias`, arbitrary owner ids match by numeric string. `DescribePlacementGroups` used to raise `InternalFailure "not implemented"` ; it now returns the AWS-shaped `{"PlacementGroups": []}`. A single-bucket `awsmap` scan drops from 1179 phantom rows to 2 real rows.

### ENI-level live security-group re-apply

Pre-1.2.0, the SG data plane only tracked instance-level SG mutations (`ModifyInstanceAttribute --groups=...`). The ENI-level control-plane operations that terraform and cdk actually generate, `AttachNetworkInterface`, `DetachNetworkInterface`, `ModifyNetworkInterfaceAttribute --groups=...`, updated moto and the AddressIndex but never touched the running container's iptables. An instance ran with the SG set it had at launch until re-created. `resolve_union_sgs_for_instance` in `services/ec2/docker/sg_reapply.py` computes the union of SG ids across every attached ENI and re-runs `apply_sg_to_container` after each ENI attribute change, so the `INPUT` / `OUTPUT` chains reflect the new posture immediately. Requires `LOCALEMU_ENI_REAL=1` (with `LOCALEMU_VPC_IP_PINNING=1` as prereq) to be effective.

### EC2 SourceDestCheck is enforced per ENI

The container's iptables FORWARD chain now installs a rule per attached ENI, keyed on either the interface name (separate-iface mode, typical for multi-VPC routers) or the source/destination IP (shared-iface mode, when two AWS-side ENIs land on the same VPC bridge and share `eth1`). The default container policy stays `-P FORWARD DROP`, and per-ENI ACCEPT rules selectively open the gate. The legacy single-NIC "quiet router" scenario is a degenerate case of the new mechanism and keeps working without changes.

Marker files in `/var/lib/localemu/source-dest-check.d/` persist per-ENI state across `docker restart`, with the filename encoding the iface (separate mode) or `<iface>-<eni_ip>` (shared mode). The kernel `net.ipv4.ip_forward` bit is set if any marker is present, cleared when none remain.

`ModifyNetworkInterfaceAttribute` targets the specific ENI in the call. `ModifyInstanceAttribute(SourceDestCheck=...)` mirrors onto the primary ENI (as in 1.1.1) and then applies the per-ENI rule on the primary's interface.

Known limitation: when the primary and a secondary share `eth1` in shared-iface mode and the primary is `SourceDestCheck=false`, the primary's plain rule allows traffic on `eth1` regardless of which AWS-side ENI it conceptually belongs to. Tracked as a 1.2.x follow-up. Single-NIC and multi-VPC (separate-iface) cases are unaffected.

### Cognito User Pool Lambda triggers, full lifecycle

The nine triggers that previously accepted a Lambda ARN at `CreateUserPool`/`UpdateUserPool` but never invoked it now fire at the right phase:

- **PreAuthentication** : before the password check in `InitiateAuth` / `AdminInitiateAuth`. Raising in the Lambda returns `NotAuthorizedException` to the caller, matching the AWS contract.
- **PostAuthentication** : after a successful `AuthenticationResult` in all four auth handlers. Side-effect only.
- **CustomMessage** : on every code-send path (`SignUp`, `ResendConfirmationCode`, `ForgotPassword`, `AdminCreateUser`, attribute verification). Override `smsMessage` / `emailMessage` / `emailSubject` lands in a per-user buffer.
- **DefineAuthChallenge** / **CreateAuthChallenge** / **VerifyAuthChallengeResponse** : the CUSTOM_AUTH flow is driven end to end. A server-side session map (5-minute idle TTL) carries private challenge parameters from `InitiateAuth` to `RespondToAuthChallenge`. Sessions are cleared on token mint or auth failure.
- **UserMigration** : on `InitiateAuth` / `AdminInitiateAuth` when the user is unknown and the auth flow is `USER_PASSWORD_AUTH` / `USER_SRP_AUTH` / `ADMIN_USER_PASSWORD_AUTH`. The Lambda's response synthesises a confirmed user with the password from the request, then auth is retried and the AuthenticationResult is returned.
- **CustomSMSSender** / **CustomEmailSender** : when configured, replace the in-memory message buffer with a Lambda invocation carrying the code as a base64-encoded blob (placeholder for the AWS KMS-encrypted shape).

The plain code that Cognito would have delivered is also stored in an in-memory buffer, queryable through a new dashboard endpoint `GET /_localemu/api/cognito-messages/<pool_id>/<username>`. Tests and tutorials can read the buffer to recover the code and complete flows (SignUp confirmation, password reset, ...) without real email or SMS delivery.

### Fully offline runtime

LocalEmu no longer contacts any external host. The AWS Transcribe emulator, the pytest marker-report uploader, the CI test-selection tool, the ffmpeg installer, the raw-GitHub fallback downloader and a handful of dead endpoint constants that were inherited from the upstream fork have all been removed or replaced with in-process equivalents. The bundled `pytest-httpserver` provides a 127.0.0.1 echo server for AWS integration tests. `utils/analytics/` remains an inert no-op shim: no counters, no fingerprint, no requests, no disk writes.

Transcribe is stubbed for this release: every operation returns an AWS-shaped `InternalFailure` explaining that the service is not implemented locally.

### Correctness fixes

- **CloudTrail** : `DeleteTrail` on a nonexistent trail returned success instead of raising `TrailNotFoundException` (moto silently no-ops instead of validating existence first).
- **EventBridge** : `PutEvents` archives with no `EventPattern` (matching every event on the bus) picked up unrelated traffic - LocalEmu's own internal API calls (CloudWatch self-metrics, SQS delivery-worker calls) were being self-recorded by CloudTrail and re-forwarded as if they were user activity, and CloudTrail-to-EventBridge forwarding had no delivery delay, unlike real AWS's asynchronous pipeline. Both fixed.
- **EC2** : `CreateVpcEndpoint` populated a DNS entry for every endpoint type ; only Interface-type endpoints get one on real AWS, Gateway endpoints route via a route-table prefix list and never have a DNS name.
- **ECS** : `ListServices` returned services after `DeleteService` because moto's `list_services` has no status filter at all. `RunTask` crashed with an unhandled `KeyError` whenever `securityGroups` was omitted from `awsvpcConfiguration`, which real AWS treats as optional (falls back to the VPC default security group).
- **IAM** : `GetRole` / `ListRoles` double-JSON-encoded `AssumeRolePolicyDocument`, so callers received a JSON string instead of a parsed policy document.
- **STS** : trust-policy evaluation compared `Effect` case-sensitively, rejecting policies using `"Effect": "ALLOW"` (uppercase), which real AWS accepts.
- **Kinesis** : requests using the `smithy-rpc-v2-cbor` wire protocol (`GetRecords`, `PutRecord`, `SubscribeToShard`, and others) crashed with a 500 error, since moto has no CBOR support at all and was receiving the raw binary body unchanged. Fixed at the dispatch boundary : LocalEmu now re-serializes to plain JSON before handing off to moto for any operation moto doesn't natively understand.
- **Dashboard** : every static asset request (JS, CSS) was rejected with a 403 whenever the container's published host port differed from its internal listen port (e.g. `docker run -p 8080:4566`), because the CORS origin check only ever knew the internal port. Loopback origins (`localhost`, `127.0.0.1`, `::1`) are now trusted regardless of port ; non-loopback origins are still rejected exactly as before.
- **Packaging** : `pip install localemu` (no extras) crashed on startup with `ModuleNotFoundError: No module named 'rolo'` - the runtime dependencies were only declared under the optional `[runtime]` extra. They're now plain dependencies of the base package, so `pip install localemu` alone is fully functional. `pip install localemu[runtime]` still works identically (verified : both installs resolve to the exact same package set) and is kept for backward compatibility ; it will be removed once the documentation is updated to only reference the bare install.

## 1.1.1

Dashboard packaging and instance-to-ENI metadata fix.

### Dashboard ships its stylesheets and scripts

The 1.1.0 wheel on PyPI shipped `index.html` and the SVG icons under `dashboard/static/`, but not the CSS or JavaScript files. The dashboard at `/_localemu/dashboard` rendered as an unstyled skeleton with no working scripts. The packaging allowlist in `pyproject.toml` now covers `dashboard/static/css/*.css` and `dashboard/static/js/**/*.js`, and the wheel ships the full asset tree. The Docker image was unaffected (editable install pulls files directly from the source tree), but `pip install localemu==1.1.0` produced the broken dashboard. Fixed in the wheel for 1.1.1.

### Instance SourceDestCheck propagates to the primary ENI

On AWS, `ModifyInstanceAttribute(SourceDestCheck=...)` updates the primary ENI's bit so `DescribeInstances` and `DescribeNetworkInterfaces` both report the same value. 1.1.0 wrote only `Instance.source_dest_check`; the per-NIC field in both describe responses stayed at the previous value. 1.1.1 mirrors the bit bidirectionally between the instance view and the primary ENI's NIC model (in moto and in the LocalEmu address index). Writes to a secondary ENI do not affect the instance-level view, matching AWS semantics.

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
access point, by ARN, alias (`<name>-<34hex>-s3alias`), or hostname
(`<name>-<account>.s3-accesspoint.<region>.amazonaws.com`), are routed
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
