<p align="center">
  <img src="https://raw.githubusercontent.com/localemu/localemu/main/docs/localemu-logo.png" alt="LocalEmu" width="120">
</p>

<h1 align="center">LocalEmu</h1>

<p align="center">
  A free, open-source AWS cloud emulator.
</p>

<p align="center">
  <a href="https://pypi.org/project/localemu/"><img alt="PyPI" src="https://img.shields.io/pypi/v/localemu?color=blue"></a>
  <a href="https://pypi.org/project/localemu/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/localemu"></a>
  <a href="https://hub.docker.com/r/localemu/localemu"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/localemu/localemu"></a>
  <a href="https://github.com/localemu/localemu/blob/main/LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-blue.svg"></a>
</p>

<p align="center">
  <img alt="Emulates AWS" src="https://img.shields.io/badge/emulates-AWS-FF9900?logo=amazonwebservices&logoColor=white">
  <img alt="AWS services" src="https://img.shields.io/badge/AWS%20services-132-1f6feb">
  <a href="https://github.com/localemu/localemu/blob/main/CONTRIBUTING.md"><img alt="PRs welcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg"></a>
  <a href="https://github.com/astral-sh/ruff"><img alt="Ruff" src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json"></a>
  <a href="https://github.com/localemu/localemu/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/localemu/localemu?color=yellow"></a>
</p>

<p align="center">
  Run AWS services locally. No account. No token. No sign-up.
</p>

<p align="center">
  <img src="docs/demo.gif" alt="LocalEmu demo: real AWS CLI against localhost:4566" width="100%">
</p>

---

## What is LocalEmu?

LocalEmu emulates 132 AWS services on your machine. Use the same AWS CLI, boto3, Terraform, or CDK you already know - just point to `localhost:4566`.

**Build and test against AWS APIs from your laptop with no account, no credentials, no internet.** The iteration loop is seconds instead of minutes; you can break, reset, and rebuild as often as you want at zero cost.

Where it counts, the behavior is real, not stubbed: Lambda runs your code in the official AWS runtime images, EC2 instances are real containers on a real VPC with security groups enforced by actual packet filtering, RDS is a real PostgreSQL or MySQL you can open a connection to, and (with `IAM_ENFORCEMENT=1`) your identity and resource policies actually deny.

## Install

```bash
pip install localemu[runtime]
```

That's it. No Java. No tokens. No accounts. Docker is required for services that emulate by running a real engine in a sidecar (Lambda, ECS, EKS via k3d, RDS, OpenSearch, EC2). Everything else is pure Python and needs no Docker.

## Start

```bash
# Foreground (see the banner and logs)
localemu start

# Detached mode (runs in background)
localemu start -d

# Custom port
localemu start --port 4567

# Stop
localemu stop
```

<p align="center">
  <img src="docs/start.gif" alt="localemu start: boot banner and ready state" width="100%">
</p>

## Use

LocalEmu ships `awsemu` - a drop-in replacement for the AWS CLI that automatically points to LocalEmu. No configuration needed:

```bash
# S3
awsemu s3 mb s3://my-bucket
awsemu s3 cp file.txt s3://my-bucket/

# DynamoDB
awsemu dynamodb create-table --table-name Users \
  --key-schema AttributeName=id,KeyType=HASH \
  --attribute-definitions AttributeName=id,AttributeType=S \
  --billing-mode PAY_PER_REQUEST

# SQS
awsemu sqs create-queue --queue-name my-queue

# Lambda
awsemu lambda create-function --function-name hello \
  --runtime python3.12 --handler handler.handler \
  --role arn:aws:iam::000000000000:role/role \
  --zip-file fileb://function.zip

# Any of the 132 supported services...
awsemu ecs create-cluster --cluster-name my-cluster
awsemu rds describe-db-instances
awsemu cognito-idp create-user-pool --pool-name my-pool
```

`awsemu` sets credentials, region, and endpoint automatically. You can also use the standard AWS CLI, boto3, Terraform, CDK, or Pulumi - just point to `http://localhost:4566`.

## Documentation & examples

The full documentation lives at [localemu.cloud/docs](https://localemu.cloud/docs): prerequisites, install guide, per-service API reference, and end-to-end use case walkthroughs.

For runnable code, clone the companion examples repository:

```bash
git clone https://github.com/localemu/localemu-examples
```

It ships self-contained tutorials covering common patterns: public + private VPC with EC2 / nginx / NACL, image pipelines, scheduled jobs, IAM least-privilege drills, Step Functions sagas, EKS + kubectl, chaos resilience tests, and more.

## Explore

```bash
# List all supported services
localemu services

# Show operations for a specific service
localemu services s3
localemu services lambda
localemu services dynamodb

# Check running services
localemu status

# Stop
localemu stop
```

## Dashboard

LocalEmu includes a built-in web dashboard for monitoring and exploring your local AWS environment in real time.

```
http://localhost:4566/_localemu/dashboard
```

The dashboard shows:
- **Service overview** with resource counts and status indicators for all active services
- **Resource drill-down**: click any service to see tables, buckets, queues, functions, instances, and more
- **S3 object browser** and **DynamoDB item viewer** with click-through navigation
- **CloudTrail event history** with expandable request/response details
- **Live activity feed** showing API calls as they happen, filterable by service

The dashboard starts automatically with LocalEmu. No configuration needed.

## Simulation Features

Test real AWS behavior locally with opt-in feature flags:

```bash
# IAM policy enforcement (full AWS evaluation algorithm, see section below)
IAM_ENFORCEMENT=1 localemu start

# API throttling simulation (per-service AWS error codes)
SIMULATE_THROTTLING=1 THROTTLE_RATE=0.05 localemu start

# Network latency injection (realistic per-service delays)
SIMULATE_LATENCY=1 localemu start

# Lambda cold start simulation
LAMBDA_COLD_START_DELAY=3 localemu start

# EC2, ECS, and EKS use real containers automatically when Docker is
# available; no env var needed. Opt out via EC2_VM_MANAGER=none,
# ECS_DOCKER_BACKEND=0, or EKS_K8S_PROVIDER=off.

# Real RDS engines (PostgreSQL / MySQL / MariaDB in containers)
RDS_DOCKER_BACKEND=1 localemu start
```

Simulation features (IAM enforcement, throttling, latency, cold-start) are disabled by default; zero overhead when off. The container-backed services turn themselves off automatically when the Docker daemon is unavailable.

## IAM Policy Enforcement

Run your AWS workload against the same policy rules AWS applies in production. Useful for catching permission errors locally before they surface in a deployed environment.

```bash
# Strict mode: deny unauthorized requests with 403 AccessDenied
IAM_ENFORCEMENT=1 localemu start

# Audit mode: log would-be denials, allow the request through
IAM_ENFORCEMENT=soft localemu start

# Bypass enforcement for specific access keys (comma-separated allow-list)
ROOT_ACCESS_KEYS=AKIAIOSFODNN7EXAMPLE IAM_ENFORCEMENT=1 localemu start
```

**What gets evaluated** (full AWS algorithm, see [policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)):

- Explicit `Deny` in any policy → deny (identity / resource / permission boundary / session).
- Same-account: either identity-policy `Allow` OR resource-policy `Allow` is sufficient.
- Permission boundary: must also `Allow` (intersection).
- Session policies (inline or managed) passed via `AssumeRole`: must also `Allow` (intersection).

**Policy elements**

| Element | Supported |
|---|---|
| `Action` / `NotAction` with wildcards `*` `?` | ✅ |
| `Resource` / `NotResource` ARN matching | ✅ |
| `Principal` / `NotPrincipal` (AWS / Service / Federated / CanonicalUser) | ✅ |
| IAM policy variables: `${aws:username}`, `${aws:userid}`, `${aws:PrincipalTag/*}` | ✅ |
| String / Numeric / Date / IpAddress / Bool / Arn / Null operators | ✅ |
| `IfExists` suffix | ✅ |
| `ForAllValues:` / `ForAnyValue:` set operators | ✅ |

**Condition context keys populated per request**

`aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalType`, `aws:SourceIp`, `aws:CurrentTime`, `aws:EpochTime`, `aws:SecureTransport` (from TLS scheme), `aws:UserAgent`, `aws:RequestedRegion`, `aws:username`, `aws:userid`, `aws:PrincipalTag/*`, `aws:RequestTag/*`, `aws:TagKeys`, and `aws:MultiFactorAuthPresent` (set to `"true"` only when the caller's session was minted by `AssumeRole` / `GetSessionToken` with `--serial-number`, otherwise absent per AWS spec).

**Temporary-credential validation**: temporary access keys (`ASIA*` / `LSIA*`) must include an `X-Amz-Security-Token`. Expired sessions return `ExpiredTokenException`.

**Limitations**

- Cross-account calls (caller account ≠ resource owner account) are currently treated as same-account. LocalEmu defaults to a single account so this rarely matters; if you emulate multi-account IAM flows, enforcement will be more permissive than AWS.
- Service-principal grants on resource policies (e.g. `Principal: {Service: lambda.amazonaws.com}`) are not auto-matched for internal service-to-service calls; use `AWS` principals or `*` for now.

## 132 Supported Services

Run `localemu services` to see the full list. Key services include: ACM, API Gateway, AppSync, Athena, Backup, Batch, Bedrock, CloudFormation, CloudFront, CloudTrail, CloudWatch, CodeBuild, CodeCommit, CodeDeploy, CodePipeline, Cognito, Config, DynamoDB, EC2, ECR, ECS, EFS, EKS, ElastiCache, ELB, ELBv2, Elasticsearch, EMR, EventBridge, Firehose, FSx, Glacier, Glue, GuardDuty, IAM, IoT, Kafka, Kinesis, KMS, Lambda, CloudWatch Logs, Neptune, OpenSearch, Organizations, Pipes, RDS, Redshift, Rekognition, Resource Groups, Route53, S3, SageMaker, Scheduler, Secrets Manager, SES, SESv2, SNS, SQS, SSM, Step Functions, STS, Textract, Transcribe, Transfer, WAFv2, X-Ray, and more.

## Python (boto3)

```python
import boto3

s3 = boto3.client("s3",
    endpoint_url="http://localhost:4566",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region_name="us-east-1",
)

s3.create_bucket(Bucket="my-bucket")
s3.put_object(Bucket="my-bucket", Key="hello.txt", Body=b"Hello!")
```

## Terraform

```hcl
provider "aws" {
  access_key                  = "AKIAIOSFODNN7EXAMPLE"
  secret_key                  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true

  endpoints {
    s3       = "http://localhost:4566"
    dynamodb = "http://localhost:4566"
    lambda   = "http://localhost:4566"
    sqs      = "http://localhost:4566"
    # all services on the same endpoint
  }
}
```

## Persistence

By default, LocalEmu state is ephemeral. To keep your resources across restarts:

```bash
# Local
PERSISTENCE=1 localemu start

# Docker
docker run -d --name localemu \
  -p 4566:4566 \
  -v localemu-data:/var/lib/localemu \
  -e PERSISTENCE=1 \
  --user root \
  localemu/localemu
```

State is saved on shutdown and restored on startup. S3 buckets, DynamoDB tables,
Lambda functions, SQS queues, Secrets Manager secrets. Everything survives.

**Save strategies** (set via `SNAPSHOT_SAVE_STRATEGY`):
- `ON_SHUTDOWN` (default): saves when LocalEmu stops
- `SCHEDULED`: saves every 15 seconds (configurable via `SNAPSHOT_FLUSH_INTERVAL`)
- `MANUAL`: save/load via `POST /_localemu/state/save` and `POST /_localemu/state/load`

**Check status:** `GET /_localemu/state/status`

## Docker (alternative)

```bash
# Linux
docker run --rm -d -p 4566:4566 -p 4510-4559:4510-4559 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add docker \
  localemu/localemu

# macOS (Docker Desktop)
docker run --rm -d -p 4566:4566 -p 4510-4559:4510-4559 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --user root \
  localemu/localemu
```

> **Why `--user root` on macOS?** Lambda, ECS, and EC2 services spawn real
> Docker containers for function execution. On Docker Desktop for Mac the
> socket is owned by `root` inside the container regardless of host GID, so
> the non-root `localemu` user cannot access it. On Linux, adding the
> `docker` group (`--group-add docker`) is sufficient.

## Using the AWS CLI with Docker

When LocalEmu runs in Docker, use the standard AWS CLI from your host:

```bash
# Option A: set the endpoint once via env var (recommended)
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_DEFAULT_REGION=us-east-1

aws s3 ls
aws dynamodb list-tables
aws lambda list-functions
```

<p align="center">
  <img src="docs/awscli-demo.gif" alt="Standard AWS CLI against LocalEmu via env vars: DynamoDB and Lambda" width="100%">
</p>

```bash
# Option B: create a host-side awsemu alias
alias awsemu='aws --endpoint-url=http://localhost:4566 --region us-east-1'
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

awsemu s3 ls
awsemu sqs list-queues
```

```bash
# Option C: use awsemu inside the container
docker exec localemu bash -c \
  '. /opt/code/localemu/.venv/bin/activate && awsemu s3 ls'
```

> **Tip:** Option A with `AWS_ENDPOINT_URL` is the cleanest: boto3 and the
> AWS CLI both read it automatically. Your code works identically on LocalEmu
> and real AWS by just unsetting the env var.

## Contributing

- [Open issues](https://github.com/localemu/localemu/issues)
- [Discussions](https://github.com/localemu/localemu/discussions)

## License

Copyright (c) 2026 TocConsulting and LocalEmu contributors.
Copyright (c) 2017-2026 LocalStack contributors.
Copyright (c) 2016 Atlassian and others.

Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

LocalEmu is a fork of [LocalStack](https://github.com/localstack/localstack), which was archived by its maintainers. We are grateful to all original contributors.
