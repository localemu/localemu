# Getting Started with LocalEmu

LocalEmu is a free, open-source AWS cloud emulator. 132 services. One install. No account, no token, no Java. Just Python.

## Install

```bash
pip install localemu[runtime]
```

## Start

```bash
localemu start
```

```
LocalEmu version: x.x.x
Ready.
```

LocalEmu is now running on `http://localhost:4566` with 132 AWS services.

## CLI Commands

```bash
localemu start              # Start all services
localemu start -d           # Start in background (detached)
localemu stop               # Stop LocalEmu
localemu status             # Show running services and their status
localemu services           # List all supported services
localemu services s3        # Show all S3 operations
localemu services lambda    # Show all Lambda operations
localemu --version          # Show version
```

## awsemu - AWS CLI for LocalEmu

`awsemu` is a built-in wrapper around the AWS CLI. It automatically sets credentials, region, and endpoint. No configuration needed:

```bash
awsemu s3 ls
awsemu dynamodb list-tables
awsemu lambda list-functions
```

It's equivalent to `aws --endpoint-url=http://localhost:4566` with dummy credentials pre-configured.

---

## S3 - Object Storage

```bash
# Create a bucket
awsemu s3 mb s3://my-bucket

# Upload a file
echo "Hello LocalEmu" > hello.txt
awsemu s3 cp hello.txt s3://my-bucket/hello.txt

# List objects
awsemu s3 ls s3://my-bucket

# Download a file
awsemu s3 cp s3://my-bucket/hello.txt downloaded.txt
cat downloaded.txt

# Delete
awsemu s3 rm s3://my-bucket/hello.txt
awsemu s3 rb s3://my-bucket
```

---

## DynamoDB - NoSQL Database

```bash
# Create a table
awsemu dynamodb create-table \
  --table-name Users \
  --key-schema AttributeName=userId,KeyType=HASH \
  --attribute-definitions AttributeName=userId,AttributeType=S \
  --billing-mode PAY_PER_REQUEST

# Insert an item
awsemu dynamodb put-item \
  --table-name Users \
  --item '{"userId":{"S":"001"},"name":{"S":"Tarek"},"role":{"S":"Engineer"}}'

# Read an item
awsemu dynamodb get-item \
  --table-name Users \
  --key '{"userId":{"S":"001"}}'

# Scan all items
awsemu dynamodb scan --table-name Users

# Delete table
awsemu dynamodb delete-table --table-name Users
```

---

## SQS - Message Queues

```bash
# Create a queue
awsemu sqs create-queue --queue-name my-queue

# Send a message
awsemu sqs send-message \
  --queue-url http://localhost:4566/000000000000/my-queue \
  --message-body "Hello from LocalEmu"

# Receive messages
awsemu sqs receive-message \
  --queue-url http://localhost:4566/000000000000/my-queue

# Delete queue
awsemu sqs delete-queue \
  --queue-url http://localhost:4566/000000000000/my-queue
```

---

## SNS - Pub/Sub Notifications

```bash
# Create a topic
awsemu sns create-topic --name my-topic

# Subscribe
awsemu sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:000000000000:my-topic \
  --protocol email \
  --notification-endpoint user@example.com

# Publish a message
awsemu sns publish \
  --topic-arn arn:aws:sns:us-east-1:000000000000:my-topic \
  --message "Hello from LocalEmu"

# List topics
awsemu sns list-topics
```

---

## Lambda - Serverless Functions

Lambda requires Docker to be running.

```bash
# Create a simple Python function
mkdir -p /tmp/lambda-test
cat > /tmp/lambda-test/handler.py << 'PYEOF'
def handler(event, context):
    name = event.get("name", "World")
    return {"statusCode": 200, "body": f"Hello, {name}! From LocalEmu Lambda."}
PYEOF

# Package it
cd /tmp/lambda-test && zip function.zip handler.py && cd -

# Create the Lambda function
awsemu lambda create-function \
  --function-name hello \
  --runtime python3.12 \
  --handler handler.handler \
  --role arn:aws:iam::000000000000:role/lambda-role \
  --zip-file fileb:///tmp/lambda-test/function.zip

# Wait for Active state (~10 seconds)
awsemu lambda get-function --function-name hello | grep State

# Invoke it
awsemu lambda invoke \
  --function-name hello \
  --cli-binary-format raw-in-base64-out \
  --payload '{"name": "Tarek"}' \
  /tmp/lambda-output.json

cat /tmp/lambda-output.json

# List functions
awsemu lambda list-functions
```

---

## KMS - Encryption Keys

```bash
awsemu kms create-key --description "My encryption key"
awsemu kms list-keys
```

---

## IAM - Identity & Access Management

```bash
awsemu iam create-user --user-name testuser
awsemu iam list-users
```

---

## Secrets Manager

```bash
awsemu secretsmanager create-secret \
  --name my-secret \
  --secret-string '{"username":"admin","password":"s3cure!"}'

awsemu secretsmanager get-secret-value --secret-id my-secret
```

---

## EC2 - Virtual Machines (mock)

```bash
awsemu ec2 describe-instances
awsemu ec2 create-vpc --cidr-block 10.0.0.0/16
awsemu ec2 create-security-group --group-name my-sg --description "My SG"
awsemu ec2 describe-security-groups
```

EC2 in LocalEmu is mock-based. It tracks state but doesn't run actual VMs.

---

## Python (boto3)

```python
import boto3

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:4566",
    aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
    aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region_name="us-east-1",
)

s3.create_bucket(Bucket="my-python-bucket")
s3.put_object(Bucket="my-python-bucket", Key="hello.txt", Body=b"Hello from Python!")
response = s3.get_object(Bucket="my-python-bucket", Key="hello.txt")
print(response["Body"].read().decode())
```

---

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
    sqs      = "http://localhost:4566"
    sns      = "http://localhost:4566"
    lambda   = "http://localhost:4566"
    iam      = "http://localhost:4566"
    # all services on the same endpoint
  }
}
```

---

## Docker (alternative)

```bash
docker run --rm -d -p 4566:4566 -p 4510-4559:4510-4559 localemu/localemu
```

---

## Dashboard

LocalEmu has a built-in web dashboard. Once LocalEmu is running, open your browser:

```
http://localhost:4566/_localemu/dashboard
```

The dashboard gives you a real-time view of all your local AWS resources: S3 buckets, DynamoDB tables, SQS queues, Lambda functions, EC2 instances, VPCs, and more. You can click into any service to see its resources, browse S3 objects, view DynamoDB items, and inspect CloudTrail event history.

The live activity feed at the bottom shows every API call as it happens.

---

## Health Check

```bash
curl http://localhost:4566/_localemu/health | python -m json.tool
```

Or use the CLI:

```bash
localemu status
```

---

## Stop

```bash
localemu stop
```

Or `Ctrl+C` if running in foreground. For Docker: `docker stop <container>`.
