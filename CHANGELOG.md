# Changelog

## 1.4.0

The dashboard at `/_localemu/dashboard` is rewritten as the LocalEmu Console: a new layout, light and dark themes, and new panels backed by request telemetry that the gateway now records for every AWS call. Alongside the Console, IAM enforcement closes several gaps where a stored policy or grant had no actual effect on authorization (Organizations SCPs, KMS grants, Cognito's admin-only sign-up setting), `sts:AssumeRoleWithWebIdentity` verifies a token's signature for the first time instead of trusting it by string match, and five more services are covered: CodeBuild, Cognito Identity, RAM, SageMaker and WAFv2.

### Layout and themes

The page is a top bar, a service navigation column, the workspace, and a live API-call panel on the right (folded under the workspace below 1180 px, navigation off-canvas below 780 px). Light and dark themes follow the OS preference until you pick one with the theme button; the choice is kept in `localStorage`. Service glyphs are monogram tiles. The fonts (IBM Plex Sans, IBM Plex Sans Condensed, JetBrains Mono, SIL Open Font License 1.1, files from the fontsource packages) ship in `dashboard/static/fonts/` with their licence texts, so the dashboard makes no request to a font CDN and works offline. The ~40 existing per-resource drills and the action modals keep their behaviour and take the new styles.

### Request telemetry

Two handlers are added to the gateway chain when the dashboard registers. One stamps the start time early in request processing, the other runs with the custom response handlers and records, for every AWS call: status, error code, server-side handling time, the calling principal (resolved with the IAM enforcer's own resolver; an unknown access key is shown as the key, not as an invented identity), the resource the call named, and whether it was an IAM denial. The same calls the CloudTrail hook skips are skipped (the dashboard's own reads, calls tagged `LocalEmu-Internal/service-call`). Other LocalEmu-to-LocalEmu calls (requests carrying `x-localemu-data`, for example CloudTrail-to-EventBridge forwarding or Lambda writing its logs) are recorded and labelled `internal`; the dashboard's write actions now send a `LocalEmu-Console/action` user-agent marker and are labelled `console`. Records are kept in memory: per-second buckets for 15 minutes, latency samples for 5 minutes, the last 500 calls and the last 200 changes. Nothing is persisted.

IAM denials: with `IAM_ENFORCEMENT=1` a call is a denial when it ends in 403 `AccessDenied` / `AccessDeniedException`. With `IAM_ENFORCEMENT=soft` the enforcer only logs `IAM AUDIT DENY` and lets the call through; a logging filter on the enforcer's logger now captures that line so the call is tagged as an audit denial, with the enforcer's reason.

New endpoints, loopback-gated like the rest of the dashboard API:

- `GET /_localemu/api/system`: version, start time, uptime, endpoint, default region, IAM enforcement mode, persistence, Docker daemon status (`ping`, version, LocalEmu-managed containers per service, classified by the `localemu.service` label and the MQ, EKS and Lambda container names), the Docker switch of each Docker-capable service, and with `BEDROCK_BACKEND=ollama` whether the Ollama sidecar exists and answers on `/api/tags`.
- `GET /_localemu/api/metrics/requests?window=`: per-second requests, 4xx, 5xx and denials, requests/s, p50 / p99, errors and denials in 15 minutes, the last denial.
- `GET /_localemu/api/calls?limit=&since=&account=`: the enriched call records. Each record is also pushed on the SSE stream as a `call` event.
- `GET /_localemu/api/changes?limit=&account=`: the latest successful mutating call per resource.
- `GET /_localemu/api/metrics/services?minutes=&account=`: calls per minute per service.

### Overview

The overview shows the endpoint with copyable `AWS_ENDPOINT_URL` exports, version, uptime, IAM enforcement mode, persistence, Docker and Bedrock backend status; a requests-per-second chart for the last 5 minutes with error and denial markers; totals (resources in the selected account, services with resources or calls, running LocalEmu containers, IAM denials in 15 minutes); a grid of all 133 registered services filterable by pinned / in use, Docker-backed, or all; and a recently-changed-resources table that updates when a change is recorded. Services without a resource counter show "not counted" instead of 0. 32 of the 133 services have a counter.

### Account switcher

The top bar selects the account the console works in. `/_localemu/api/overview` and `/_localemu/api/resources/<service>` accept `?account=<12 digits>`: the counters and listers run through `_iter_moto_backends` and a new `_iter_stores` helper that skip other accounts for the duration of the request (no parameter means all accounts, as before). Write actions run in the selected account. `/_localemu/api/accounts/<id>/summary` now uses the same counters; it used to add up the length of every dict and list attribute of each moto backend, which counted internal bookkeeping as resources and returned 0 for S3, SQS, Lambda and KMS, whose state is not in moto. The Accounts page creates accounts from a form instead of browser prompts; its create and delete called `DASH.api.invalidate`, which did not exist.

### Other changes

- Command palette (`Cmd+K`, `Ctrl+K` or `/`) over all registered services, the resources of the services in use in the selected account, and actions.
- New write actions: create an S3 bucket, SQS queue, SNS topic or DynamoDB table, and purge an SQS queue. Other services' Create button shows their sample CLI command.
- The live panel shows status and error code, resource, principal, account and handling time, filters by errors, writes, account or LocalEmu-internal calls, pauses and resumes without losing the calls received meanwhile, and expands a call to its CloudTrail record.
- The CloudTrail page filters by account and service over the whole event store and shows the principal of each event.

### IAM enforcement: stored policies that had no effect

Three previously-stored-but-unconsulted controls now actually authorize or deny:

- **Organizations SCPs.** A Service Control Policy attached to the root, an OU or an account was accepted and stored (moto's native Organizations backend) but never read during evaluation, so a Deny SCP had zero effect — any identity with a permissive IAM policy could still perform the action the SCP was meant to block. The evaluator now consults the attached SCPs and an explicit Deny there overrides an identity-policy Allow, same as real AWS.
- **KMS grants.** `kms:CreateGrant` stored the grant, but the enforcer only ever read moto's native KMS backend, which LocalEmu's own KMS provider never populates (the same gap S3 had). A grant authorized nothing. Grants are now read from LocalEmu's own KMS store and scoped correctly: a grant authorizes only its covered operations, only for its grantee, only on the key it was issued against.
- **Cognito `AllowAdminCreateUserOnly`.** A user pool configured to require admin-created accounts still let anyone self-register with a plain `SignUp` call, because the setting was stored but never checked. `SignUp` now rejects with the real AWS error when the pool requires admin-created users.

New condition-key support feeding into all of the above: `aws:PrincipalTag/<key>` resolves from the caller's IAM user/role tags, and `aws:ResourceTag/<key>` resolves from each target service's own tag store (best-effort — a resource with no tags or an unrecognized ARN shape falls through to the next statement, same as AWS). A VPC Interface endpoint's own policy is now evaluated too: each endpoint gets a dedicated local listener port instead of sharing the edge port, and the IAM handler reads `aws:SourceVpce` / `aws:SourceVpc` from the port a connection arrived on (Docker Desktop NATs all container traffic to one host address, so source IP can't carry this signal).

A new in-memory, queryable decision log replaces grep-ing the server log for "why was this denied": `GET /_localemu/iam/decisions` (filterable by `principal_arn`, `action`, `resource`, `decision`) and `POST /_localemu/iam/decisions/clear`. Each entry carries the decision, the resolved reason, which policy type decided it (SCP / identity / resource / boundary / session), and the matched statement. It's a bounded 2000-entry ring buffer, not a persisted audit trail — it resets on restart like every other in-memory LocalEmu store.

### STS: real signature verification for AssumeRoleWithWebIdentity

LocalEmu previously accepted any `sts:AssumeRoleWithWebIdentity` token structurally — including one with no signature or a garbage one — as long as the trust policy's `Principal: {Federated: ...}` matched by string. The token's signature is now verified against the registered OIDC provider's real JWKS, fetched over HTTPS from the provider's well-known URL exactly like AWS does (3s timeout, 5-minute cache).

For local lab and test use where reaching the real external provider isn't possible or desired, `POST /_localemu/api/oidc/mint-token` mints a token signed with a LocalEmu-generated per-provider keypair, so a trust policy that references a real provider (e.g. `token.actions.githubusercontent.com`) can be exercised locally with a token that passes real verification — useful for demonstrating an overly-broad trust condition without needing a real workflow run at that provider. This is a LocalEmu-only convenience, not an AWS API.

### New services

CodeBuild, Cognito Identity, RAM and SageMaker join the registry as moto passthroughs with targeted patches; WAFv2 gets a real evaluator.

- **CodeBuild**: moto has no `UpdateProject` at all (not a stub — absent), so a blue-team fix that disables `privilegedMode` or moves secrets to Secrets Manager had nothing to call. `UpdateProject` now merges the same optional fields `CreateProject` accepts onto the existing project.
- **Cognito Identity**: moto creates identity pools and identities but has no role attachment and returns fixed fake credentials. `SetIdentityPoolRoles`, `GetIdentityPoolRoles` and `GetCredentialsForIdentity` are implemented for real: the role is chosen the way AWS chooses it (unauthenticated callers get the pool's `unauthenticated` role if allowed, authenticated callers get `authenticated` unless a role mapping picks another one), the role's trust policy must actually trust `cognito-identity.amazonaws.com` with matching `:aud`/`:amr` conditions, and a login issued by a LocalEmu Cognito user pool is verified cryptographically.
- **RAM**: resource shares were recorded but nothing else consulted them, so a resource shared with another account never actually appeared there. Scoped to EC2 subnets for now: a subnet shared via RAM is now visible to the account it was shared with.
- **SageMaker**: a notebook instance's `OnStart` lifecycle script now runs.
- **WAFv2**: real-time Web ACL rule evaluation (rules in ascending `Priority` order, `Block`/`Allow` terminate evaluation, `Count` doesn't) against an ALB, with its own decision log mirroring the IAM one.

### Cognito: ID-token claims

Custom and profile user attributes (`SignUp`/`AdminCreateUser` custom attributes, `given_name`, `email`, etc.) now appear as claims in the ID token Cognito issues, instead of being stored but omitted.

### CloudTrail

- The `userIdentity` on a recorded event now reflects the real caller shape (root, IAM user, assumed role with its issuing role's own ARN under `sessionContext.sessionIssuer`, or `AWSAccount`/`ANONYMOUS_PRINCIPAL` for an anonymous call) instead of a generic fallback.
- CloudTrail-to-EventBridge forwarding delay is now modeled per-service instead of one flat delay (IAM events deliver before SQS events, for example), matching the relative ordering real AWS exhibits.

### Lambda: two stuck-forever states fixed

- A version that reached `State.Failed` during startup (Docker unavailable, image pull failure) was popped out of the starting-versions tracking without ever being added to the running-versions tracking. `DeleteFunction` and `UpdateFunctionConfiguration` both call `stop_version` on every version unconditionally, and finding the ARN in neither dict raised `ValueError`, aborting the whole call — leaving the function permanently undeletable and unupdatable. `stop_version` on an untracked ARN is now a no-op.
- A version whose `prepare_version` (Docker image pull / runtime init) hung had no timeout at all, leaving it in `Pending` forever and making `UpdateFunctionConfiguration` fail with "cannot be updated if an old one is not running," with no way out. `prepare_version` now has a ceiling (`LAMBDA_VERSION_START_TIMEOUT_SECONDS`, 0 to disable) and the version is moved to `State.Failed` with a clear reason instead of hanging.

### EKS: endpointPrivateAccess

`endpointPrivateAccess` on a cluster is now threaded into a real network-isolation decision (the cluster's API server joins the VPC's Docker bridge and the public port is firewalled) instead of being accepted and ignored. The default (unset/false) path is unchanged.

### IAM: smaller fixes

- Re-setting a managed policy's default version to the version that's already the default is now a no-op, matching real AWS (it previously errored).
- A trust policy naming an IAM user or role, in enforcement mode, is now validated: it may only name a user or role that actually exists.

### Other fixes

- `localemu status`: service state colors were backwards — `running` showed yellow and the dormant `available` state showed green, the opposite of what every other CLI traffic-light convention means. `running` is green, `available` is a dim grey circle.
- `events:PutEvents` IAM enforcement always resolved the request's resource to the `default` event bus, because `EventBusName` is nested inside each `Entries[]` item rather than a top-level request parameter — the generic ARN resolver only read the top level. A policy scoped to a custom bus could therefore never authorize a `PutEvents` call that was correctly routed to that bus, even though the call itself worked. The resolver now reads the bus from the first entry for `PutEvents`; every other `events:*` action (`PutRule`, etc.), which does carry `EventBusName` at the top level, is unaffected.

## 1.3.2

Two fixes found by running the examples on a Linux Docker host: OpenSearch domains created by LocalEmu running in Docker now become active, and Firehose delivers the records of a Kinesis source stream.

### OpenSearch domain stuck in Processing

When LocalEmu runs in Docker, its readiness check of a new domain used `http://localhost:<published port>`. Inside the LocalEmu container that address is the container itself, not the Docker host, so the check never succeeded. The domain stayed `Processing=true` after the 60 second timeout, and `terraform apply` of an `aws_opensearch_domain` waited on it indefinitely. The check now probes the domain container's own address on the Docker network first and keeps `localhost:<port>` as the fallback, and the timeout is 120 seconds.

### Firehose with a Kinesis stream as its source

A `KinesisStreamAsSource` delivery stream accepted its configuration, but no record reached the destination. The Kinesis consumer passed the raw record bytes to the delivery code, which base64-decodes `Data`, so every batch failed with `Incorrect padding` in the log. The records are now re-encoded like the ones of a PutRecord request, and S3 receives them.

## 1.3.1

`bedrock-runtime` `InvokeModel` accepts Bedrock model ids that are not in the 21-model catalog, so applications that target newer models run locally.

### InvokeModel model ids

1.3.0 rejected any model id outside the catalog with `ValidationException: The provided model identifier is invalid`. That broke applications written for newer models, for example `anthropic.claude-sonnet-4-6-v1:0` or an Amazon Nova model, even though the same call works on AWS.

- A well-formed id from a known Bedrock provider (`provider.model-name`, optionally with a `:<n>` suffix) is now accepted, as a plain id, a `foundation-model` ARN, or a `us.`, `eu.` or `apac.` inference-profile id. A malformed id still returns `ValidationException`.
- `BEDROCK_BACKEND=synthetic` answers every accepted id.
- `BEDROCK_BACKEND=ollama` serves any `anthropic.claude-*` id that is not in the model map with the same stand-in as the listed Claude models (`llama3.1:8b`, `different_family`). Claude has no open weights, so the answer never comes from Claude.
- With `ollama`, an accepted id that is not in the model map and is not a Claude id returns `ValidationException` and tells you to use the synthetic backend.

The README now lists the full model mapping (all 21 entries, the Claude fallback and the validation rules).

### Cleanup of inherited edition labels

LocalEmu is one open-source edition, so the leftovers of the upstream editions are gone:

- `/_localemu/health` and `/_localemu/info` no longer return an `edition` field (it was always `"community"`), and `openapi.yaml` matches.
- The Docker image marker `.community-version` is now `.docker-image`, and `.pro-version` is no longer checked.
- Removed the unused `DOCKER_IMAGE_NAME_PRO` constant, the `on_pro_infra_start` hook, the `pro` option of the `container` test fixture and the unused `scripts/tinybird` tooling.
- The dev tooling classes named `Community...` are renamed, and comments that mention LocalStack Pro or a community edition were reworded.

## 1.3.0

Bedrock model catalog and `bedrock-runtime` `InvokeModel` (synthetic by default, real local inference via Ollama opt-in), native GuardDuty findings wired to EventBridge, the `aws:TokenIssueTime` IAM condition key, and `EXTRA_CORS_ALLOWED_ORIGINS` honoured by the dashboard's write actions.

### Bedrock foundation-model catalog

Moto's Bedrock backend has no route for `/foundation-models`, so `ListFoundationModels` and `GetFoundationModel` failed with `No moto route for service bedrock`. Both are now answered natively from a curated catalog (`services/bedrock/catalog.py`) covering Anthropic Claude 3.x, Amazon Titan, Meta Llama 3/3.1/3.2, Mistral/Mixtral, Cohere and AI21 Jamba, with `byProvider` and `byOutputModality` filtering. Newer providers (DeepSeek, Qwen, GLM, gpt-oss, Nemotron) are not in the catalog because their exact Bedrock model ids were not verified. Every other Bedrock operation stays on the existing moto path.

### bedrock-runtime `InvokeModel`

New `bedrock-runtime` provider (registered in `plux.ini` and `services/providers.py`). `InvokeModel` validates its input like Bedrock: an unknown model id (a bare id, a `foundation-model` ARN or a `us.`/`eu.`/`apac.` inference-profile id of a catalog model is accepted) and a body that is empty, not JSON or not a JSON object both return `ValidationException`. Only `InvokeModel` is implemented; every other operation (`Converse`, streaming) returns a 501 `InternalFailure` reading `no handler for operation '<name>' on service 'bedrock-runtime'`. `BEDROCK_BACKEND` selects the backend:

- `synthetic` (default) : deterministic placeholder output shaped like each model family's real response body (Anthropic Messages, Titan, Llama, Mistral, Cohere), so application code parses it unchanged. Same prompt gives the same output. No Docker, no download.
- `ollama` : real generation and embeddings from a local model in a Docker sidecar, pulled on first use. A model-to-Ollama-tag table (`local_inference.py`) marks each entry `same_family`, `different_family` (for example Claude served by `llama3.1:8b`) or `unavailable` (405B, closed-weight Mistral Large, Jamba). A RAM pre-flight (`memory_gate.py`) compares total physical RAM against the model's tier (16/32/64 GB) and returns a `ServiceQuotaExceededException` before attempting the pull, instead of stalling the machine.

The README documents measured RAM and first-load times and the cost of switching between two large models on a 16 GB machine.

### GuardDuty findings

Moto implements detectors and filters but has no route for the finding plane, so these operations failed with `No moto route`. They are now native (`services/guardduty/findings_store.py`), on a persisted store keyed by account, region and detector:

- `CreateSampleFindings`, `ListFindings`, `GetFindings`.
- `ArchiveFindings` and `UnarchiveFindings` (the `Service.Archived` flag), `UpdateFindingsFeedback` (`Service.UserFeedback`) and `GetFindingsStatistics` (`COUNT_BY_SEVERITY` plus `GroupBy` account, date, finding type, resource and severity).
- `ListFilters`, which moto also lacked.
- `DeleteDetector` now also removes the detector's findings.

`FindingCriteria` works on any dotted field path (`type`, `severity`, `service.archived`, `resource.resourceType`, `updatedAt`, ...) with `Eq`, `Neq`, `Equals`, `NotEquals`, `Gt`, `Gte`, `Lt`, `Lte` and their long names, `Matches` and `NotMatches`. Timestamps compare as epoch milliseconds, as in AWS, and a field a finding does not have never satisfies a positive condition. `SortCriteria` is honored by `ListFindings` and `GetFindings`. Findings survive `PERSISTENCE=1` restarts and state save and load.

Finding types follow the `<category>:<resourceClass>/<threatName>` convention; a curated table gives real titles, descriptions and severities for the common types, and any other type gets a schema-valid finding derived from the type string. `CreateSampleFindings` publishes each finding to the account's default EventBridge bus (`source: aws.guardduty`, `detail-type: GuardDuty Finding`), so a GuardDuty -> EventBridge -> Lambda pipeline runs against the real API without a synthetic `put-events` step. Detector and filter create, get and update operations are unchanged.

### IAM `aws:TokenIssueTime`

The condition key was absent from the request context, so any policy conditioned on it silently never matched. STS now records `issued_at` on every session it mints (`AssumeRole`, the SAML and web-identity variants, `GetSessionToken` and `GetFederationToken`), and the enforcer exposes it as an ISO-8601 UTC string. The incident-response pattern of denying every session issued before a containment timestamp (`Deny` with `DateLessThan` on `aws:TokenIssueTime`) now works. The key is also set for `GetSessionToken` and `GetFederationToken` sessions. Long-term IAM-user keys and sessions created before this version (no recorded `issued_at`) do not get it.

### GetSessionToken and GetFederationToken credentials work under IAM enforcement

With `IAM_ENFORCEMENT=1`, credentials from `GetSessionToken` and `GetFederationToken` were rejected as "security token invalid". They now resolve to the caller: `GetSessionToken` credentials act as the IAM user (or as root, for the root account) and `GetCallerIdentity` returns the user ARN. `GetFederationToken` credentials are `federated-user/<Name>`: the user's policies intersected with the `Policy` passed in the call, and no permissions at all when no policy is passed, as in AWS. Credentials stop working at their expiry. `sts:GetSessionToken` needs no IAM permission, as in AWS; `sts:GetFederationToken` does.

### IAM actions for Bedrock Runtime

`InvokeModel` is authorized as the real AWS action `bedrock:InvokeModel` (AWS has no `bedrock-runtime:` IAM namespace) on `arn:aws:bedrock:<region>::foundation-model/<model-id>`, so policies written for AWS work, including ones scoped to a single model. `Converse` maps to `bedrock:InvokeModel`, and the streaming operations to `bedrock:InvokeModelWithResponseStream`.

### Dashboard behind a custom hostname

The dashboard's write actions rejected any non-loopback `Origin`, even when `EXTRA_CORS_ALLOWED_ORIGINS` already allowed it for the rest of the API. They now accept hostnames listed in that variable. The CORS-blocked log line and the dashboard 403 message name the variable, and the README documents it next to `DASHBOARD_API_OPEN=1`.

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
and reproduced using an EC2 security scanner against LocalEmu 1.0.0.
The S3 replication and S3 Access Point data planes were prioritized
to unblock the matching attack labs in a security-research project.
