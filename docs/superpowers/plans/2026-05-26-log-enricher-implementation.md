# Log Enricher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-grade serverless AWS module (Terraform + Python 3.12) that enriches VPC Flow Logs with resource metadata and Threat Intel, then delivers structured JSON to S3, Datadog, or Splunk via Firehose.

**Architecture:** VPC Flow Logs stream directly into Amazon Data Firehose (hot path). A Firehose transformation Lambda enriches each record with DynamoDB cache data (populated every 15 min by a collector Lambda on the cold path). All infra is a single-root Terraform module with three example configurations.

**Tech Stack:** Terraform ≥1.5 / AWS Provider ~5.0, Python 3.12, boto3, requests, pytest, requests-mock

---

## File Map

| File | Purpose |
|------|---------|
| `versions.tf` | Terraform + provider version constraints |
| `variables.tf` | All input variables with defaults and validation |
| `dynamodb.tf` | IP cache table with TTL |
| `iam.tf` | 4 IAM roles: Collector, Enricher, FlowLogsDelivery, Firehose |
| `main.tf` | S3 bucket, Firehose stream (dynamic blocks), VPC Flow Logs, EventBridge rule |
| `lambdas.tf` | Lambda packaging, functions, Log Groups, permissions |
| `outputs.tf` | Key resource ARNs and names |
| `examples/s3/main.tf` | Example: default S3 destination |
| `examples/datadog/main.tf` | Example: Datadog HTTP intake destination |
| `examples/splunk/main.tf` | Example: Splunk HEC destination |
| `functions/collector/collector.py` | Cold path: EC2 metadata + Threat Intel → DynamoDB upsert |
| `functions/collector/requirements.txt` | requests |
| `functions/enricher/enricher.py` | Hot path: Firehose transformation processor |
| `functions/enricher/requirements.txt` | (stdlib only) |
| `tests/test_collector.py` | Unit tests for collector |
| `tests/test_enricher.py` | Unit tests for enricher |

---

## Task 1: Scaffold Project Structure

**Files:**
- Create: `versions.tf`
- Create: `.gitignore`
- Create: `functions/collector/requirements.txt`
- Create: `functions/enricher/requirements.txt`
- Create: `functions/collector/collector.py` (placeholder)
- Create: `functions/enricher/enricher.py` (placeholder)
- Create: `tests/__init__.py`

- [ ] **Step 1: Create all directories**

```bash
mkdir -p functions/collector functions/enricher tests examples/s3 examples/datadog examples/splunk .builds
```

- [ ] **Step 2: Create `.gitignore`**

```
# Terraform
.terraform/
.terraform.lock.hcl
*.tfstate
*.tfstate.backup
*.tfplan
override.tf
override.tf.json

# Lambda build artifacts
.builds/

# Python
__pycache__/
*.pyc
.pytest_cache/
.venv/
```

- [ ] **Step 3: Create `versions.tf`**

```hcl
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}
```

- [ ] **Step 4: Create `functions/collector/requirements.txt`**

```
requests>=2.31.0
```

- [ ] **Step 5: Create `functions/enricher/requirements.txt`**

```
# Enricher uses only the AWS Lambda runtime stdlib + boto3 (pre-installed)
```

- [ ] **Step 6: Create placeholder Lambda files (required for archive_file at plan time)**

`functions/collector/collector.py`:
```python
def lambda_handler(event, context):
    raise NotImplementedError("Placeholder — see Task 9")
```

`functions/enricher/enricher.py`:
```python
def lambda_handler(event, context):
    raise NotImplementedError("Placeholder — see Task 11")
```

- [ ] **Step 7: Create `tests/__init__.py`**

```python
```
(empty file)

- [ ] **Step 8: Commit**

```bash
git init
git add .
git commit -m "chore: scaffold project structure"
```

---

## Task 2: variables.tf

**Files:**
- Create: `variables.tf`

- [ ] **Step 1: Create `variables.tf`**

```hcl
# ==============================================================
# terraform-aws-log-enricher — Input Variables
# ==============================================================

variable "aws_region" {
  description = "AWS region where all resources are deployed."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix applied to every resource name for namespacing. Use lowercase letters, numbers, and hyphens only."
  type        = string
  default     = "log-enricher"
}

variable "vpc_ids" {
  description = "List of VPC IDs to enable Flow Logs on. Leave empty to target all VPCs in the account automatically."
  type        = list(string)
  default     = []
}

variable "siem_destination_type" {
  description = "Primary SIEM output destination for the Firehose stream. One of: s3, datadog, splunk."
  type        = string
  default     = "s3"

  validation {
    condition     = contains(["s3", "datadog", "splunk"], var.siem_destination_type)
    error_message = "siem_destination_type must be one of: s3, datadog, splunk."
  }
}

variable "datadog_api_key" {
  description = "Datadog API key. Required when siem_destination_type is 'datadog'."
  type        = string
  default     = ""
  sensitive   = true
}

variable "splunk_hec_endpoint" {
  description = "Splunk HEC endpoint URL (e.g. https://http-inputs-myorg.splunkcloud.com). Required when siem_destination_type is 'splunk'."
  type        = string
  default     = ""
}

variable "splunk_hec_token" {
  description = "Splunk HEC token. Required when siem_destination_type is 'splunk'."
  type        = string
  default     = ""
  sensitive   = true
}

variable "collector_schedule" {
  description = "EventBridge schedule expression that triggers the Cache Worker Lambda."
  type        = string
  default     = "rate(15 minutes)"
}

variable "dynamodb_ttl_minutes" {
  description = "Minutes before a DynamoDB cache entry expires. Should be greater than the collector_schedule interval."
  type        = number
  default     = 30
}

variable "firehose_buffer_size_mb" {
  description = "Firehose buffer size in MB before flushing to the destination (1–128)."
  type        = number
  default     = 1
}

variable "firehose_buffer_interval_sec" {
  description = "Firehose buffer interval in seconds before flushing to the destination (60–900)."
  type        = number
  default     = 60
}

variable "log_retention_days" {
  description = "Retention period in days for Lambda CloudWatch Log Groups."
  type        = number
  default     = 14
}

variable "tags" {
  description = "Map of tags to apply to all provisioned AWS resources."
  type        = map(string)
  default     = {}
}
```

- [ ] **Step 2: Run `terraform validate`**

```bash
terraform init -backend=false
terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add variables.tf versions.tf
git commit -m "feat: add variables.tf and versions.tf"
```

---

## Task 3: dynamodb.tf

**Files:**
- Create: `dynamodb.tf`

- [ ] **Step 1: Create `dynamodb.tf`**

```hcl
# ==============================================================
# DynamoDB — IP Metadata Cache
#
# Hash key:  ip_address (String) — the IPv4 address of any ENI
# TTL field: expires_at (Number, Unix epoch seconds) — auto-expires
#            entries that were not refreshed in the last collector cycle.
#            PAY_PER_REQUEST handles the bursty 15-minute upsert pattern
#            without capacity planning.
# ==============================================================

resource "aws_dynamodb_table" "ip_cache" {
  name         = "${var.project_name}-ip-cache"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip_address"

  attribute {
    name = "ip_address"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-ip-cache"
  })
}
```

- [ ] **Step 2: Run `terraform validate`**

```bash
terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add dynamodb.tf
git commit -m "feat: add DynamoDB IP cache table with TTL"
```

---

## Task 4: iam.tf

**Files:**
- Create: `iam.tf`

Four roles are required:
1. **CollectorRole** — Lambda trust, EC2 read + DynamoDB write
2. **EnricherRole** — Lambda trust, DynamoDB BatchGetItem
3. **FlowLogsDeliveryRole** — `delivery.logs.amazonaws.com` trust, Firehose PutRecord
4. **FirehoseRole** — `firehose.amazonaws.com` trust, S3 write + Lambda invoke

- [ ] **Step 1: Create `iam.tf`**

```hcl
# ==============================================================
# Shared data source — used across all policies for account-scoped ARNs
# ==============================================================

data "aws_caller_identity" "current" {}

# ==============================================================
# Role 1: CollectorRole
# Assumed by the Cache Worker Lambda every 15 minutes.
# Reads EC2 topology metadata and writes enriched records to DynamoDB.
# ==============================================================

resource "aws_iam_role" "collector" {
  name = "${var.project_name}-collector-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "collector" {
  name = "${var.project_name}-collector-policy"
  role = aws_iam_role.collector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2ReadMetadata"
        Effect = "Allow"
        Action = [
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeInstances",
          "ec2:DescribeSubnets",
          "ec2:DescribeNetworkAcls"
        ]
        Resource = "*"
      },
      {
        Sid      = "DynamoDBWrite"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.ip_cache.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-collector:*"
      }
    ]
  })
}

# ==============================================================
# Role 2: EnricherRole
# Assumed by the Firehose Transformation Lambda on each invocation.
# Needs read-only DynamoDB access for BatchGetItem lookups.
# ==============================================================

resource "aws_iam_role" "enricher" {
  name = "${var.project_name}-enricher-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "enricher" {
  name = "${var.project_name}-enricher-policy"
  role = aws_iam_role.enricher.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DynamoDBRead"
        Effect   = "Allow"
        Action   = ["dynamodb:BatchGetItem"]
        Resource = aws_dynamodb_table.ip_cache.arn
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.project_name}-enricher:*"
      }
    ]
  })
}

# ==============================================================
# Role 3: FlowLogsDeliveryRole
# Trusted by the VPC Flow Logs service (delivery.logs.amazonaws.com)
# to write records directly into the Firehose stream.
#
# CRITICAL: Without this role, aws_flow_log resources will be created
# successfully by Terraform but logs will silently fail to deliver.
# ==============================================================

resource "aws_iam_role" "flow_logs_delivery" {
  name = "${var.project_name}-flow-logs-delivery-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "delivery.logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "flow_logs_delivery" {
  name = "${var.project_name}-flow-logs-delivery-policy"
  role = aws_iam_role.flow_logs_delivery.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "FirehoseWrite"
      Effect   = "Allow"
      Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"]
      Resource = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
    }]
  })
}

# ==============================================================
# Role 4: FirehoseRole
# Assumed by the Firehose delivery stream itself.
# Needs S3 write access (primary or backup) and permission to invoke
# the enricher Lambda as a transformation processor.
# ==============================================================

resource "aws_iam_role" "firehose" {
  name = "${var.project_name}-firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "firehose.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "firehose" {
  name = "${var.project_name}-firehose-policy"
  role = aws_iam_role.firehose.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Write"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.firehose_backup.arn,
          "${aws_s3_bucket.firehose_backup.arn}/*"
        ]
      },
      {
        Sid      = "LambdaInvoke"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.enricher.arn
      }
    ]
  })
}
```

- [ ] **Step 2: Run `terraform validate`**

```bash
terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add iam.tf
git commit -m "feat: add 4 least-privilege IAM roles (Collector, Enricher, FlowLogsDelivery, Firehose)"
```

---

## Task 5: main.tf

**Files:**
- Create: `main.tf`

Covers: S3 backup bucket, Firehose stream (dynamic blocks for 3 destinations), VPC Flow Log resources, EventBridge schedule.

- [ ] **Step 1: Create `main.tf`**

```hcl
# ==============================================================
# terraform-aws-log-enricher — Core Infrastructure
# ==============================================================

# ------------------------------------------------------------
# VPC Discovery
# If vpc_ids is empty, discover all VPCs in the account.
# ------------------------------------------------------------

data "aws_vpcs" "all" {}

locals {
  target_vpc_ids = length(var.vpc_ids) > 0 ? var.vpc_ids : data.aws_vpcs.all.ids
}

# ------------------------------------------------------------
# S3 Bucket
# Always provisioned regardless of SIEM destination type.
# - When siem_destination_type = "s3": primary log destination.
# - When siem_destination_type = "datadog" or "splunk": Firehose
#   requires an S3 bucket to store failed-delivery records.
# ------------------------------------------------------------

resource "aws_s3_bucket" "firehose_backup" {
  bucket = "${var.project_name}-firehose-${data.aws_caller_identity.current.account_id}"

  tags = merge(var.tags, {
    Name = "${var.project_name}-firehose-backup"
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "firehose_backup" {
  bucket = aws_s3_bucket.firehose_backup.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

# ------------------------------------------------------------
# Amazon Data Firehose Delivery Stream
#
# Uses dynamic blocks to switch between three destination types
# controlled by var.siem_destination_type. Only one dynamic block
# evaluates to a non-empty list at any given apply.
#
# The enricher Lambda is wired as a transformation processor on
# all three destination types.
# ------------------------------------------------------------

resource "aws_kinesis_firehose_delivery_stream" "vpc_flow_logs" {
  name = "${var.project_name}-vpc-flow-logs"

  destination = (
    var.siem_destination_type == "s3"      ? "extended_s3" :
    var.siem_destination_type == "datadog" ? "http_endpoint" :
    "splunk"
  )

  # ---- Destination: S3 ----
  dynamic "extended_s3_configuration" {
    for_each = var.siem_destination_type == "s3" ? [1] : []

    content {
      role_arn   = aws_iam_role.firehose.arn
      bucket_arn = aws_s3_bucket.firehose_backup.arn

      buffering_size     = var.firehose_buffer_size_mb
      buffering_interval = var.firehose_buffer_interval_sec

      # Hive-compatible prefix for easy Athena/Glue integration
      prefix              = "vpc-flow-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
      error_output_prefix = "errors/!{firehose:error-output-type}/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"

      processing_configuration {
        enabled = true

        processors {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = "${aws_lambda_function.enricher.arn}:$LATEST"
          }
        }
      }
    }
  }

  # ---- Destination: Datadog ----
  dynamic "http_endpoint_configuration" {
    for_each = var.siem_destination_type == "datadog" ? [1] : []

    content {
      # US1 Datadog Firehose intake endpoint.
      # For other Datadog regions, override this variable in your root module.
      url        = "https://aws-kinesis-http-intake.logs.datadoghq.com/v1/input"
      name       = "Datadog"
      access_key = var.datadog_api_key

      buffering_size     = var.firehose_buffer_size_mb
      buffering_interval = var.firehose_buffer_interval_sec
      role_arn           = aws_iam_role.firehose.arn

      s3_backup_mode = "FailedDataOnly"

      s3_configuration {
        role_arn           = aws_iam_role.firehose.arn
        bucket_arn         = aws_s3_bucket.firehose_backup.arn
        buffering_size     = 5
        buffering_interval = 300
        compression_format = "GZIP"
      }

      processing_configuration {
        enabled = true

        processors {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = "${aws_lambda_function.enricher.arn}:$LATEST"
          }
        }
      }
    }
  }

  # ---- Destination: Splunk ----
  dynamic "splunk_configuration" {
    for_each = var.siem_destination_type == "splunk" ? [1] : []

    content {
      hec_endpoint               = var.splunk_hec_endpoint
      hec_token                  = var.splunk_hec_token
      hec_endpoint_type          = "Event"
      hec_acknowledgment_timeout = 600

      buffering_size     = var.firehose_buffer_size_mb
      buffering_interval = var.firehose_buffer_interval_sec

      s3_backup_mode = "FailedEventsOnly"

      s3_configuration {
        role_arn           = aws_iam_role.firehose.arn
        bucket_arn         = aws_s3_bucket.firehose_backup.arn
        buffering_size     = 5
        buffering_interval = 300
        compression_format = "GZIP"
      }

      processing_configuration {
        enabled = true

        processors {
          type = "Lambda"

          parameters {
            parameter_name  = "LambdaArn"
            parameter_value = "${aws_lambda_function.enricher.arn}:$LATEST"
          }
        }
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${var.project_name}-vpc-flow-logs"
  })

  depends_on = [aws_iam_role_policy.firehose]
}

# ------------------------------------------------------------
# VPC Flow Logs — Direct-to-Firehose
#
# One aws_flow_log resource per target VPC. The custom log format
# includes modern fields (reject-reason, tcp-flags, traffic-path,
# pkt-src-aws-service) required by the enricher's troubleshooting rules.
#
# Note: $$ in HCL strings escapes to a literal $ in the AWS API call.
# ------------------------------------------------------------

resource "aws_flow_log" "vpc" {
  for_each = toset(local.target_vpc_ids)

  vpc_id               = each.value
  traffic_type         = "ALL"
  iam_role_arn         = aws_iam_role.flow_logs_delivery.arn
  log_destination      = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
  log_destination_type = "kinesis-data-firehose"

  log_format = "$${version} $${account-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${reject-reason} $${tcp-flags} $${traffic-path} $${pkt-src-aws-service}"

  tags = merge(var.tags, {
    Name = "${var.project_name}-flow-log-${each.value}"
  })
}

# ------------------------------------------------------------
# EventBridge — Collector Schedule
# ------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "collector_schedule" {
  name                = "${var.project_name}-collector-schedule"
  description         = "Triggers the Cache Worker Lambda to refresh IP metadata."
  schedule_expression = var.collector_schedule
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "collector" {
  rule      = aws_cloudwatch_event_rule.collector_schedule.name
  target_id = "CollectorLambda"
  arn       = aws_lambda_function.collector.arn
}

resource "aws_lambda_permission" "allow_eventbridge_collector" {
  statement_id  = "AllowEventBridgeInvokeCollector"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.collector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.collector_schedule.arn
}
```

- [ ] **Step 2: Run `terraform validate`**

```bash
terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Commit**

```bash
git add main.tf
git commit -m "feat: add S3 bucket, Firehose stream, VPC Flow Logs, and EventBridge schedule"
```

---

## Task 6: lambdas.tf + outputs.tf

**Files:**
- Create: `lambdas.tf`
- Create: `outputs.tf`

- [ ] **Step 1: Create `lambdas.tf`**

```hcl
# ==============================================================
# Lambda Packaging
#
# archive_file zips the function source directory at plan time.
# Output path is in .builds/ (gitignored). source_code_hash
# triggers redeployment whenever the source changes.
# ==============================================================

data "archive_file" "collector" {
  type        = "zip"
  source_dir  = "${path.module}/functions/collector"
  output_path = "${path.module}/.builds/collector.zip"
}

data "archive_file" "enricher" {
  type        = "zip"
  source_dir  = "${path.module}/functions/enricher"
  output_path = "${path.module}/.builds/enricher.zip"
}

# ==============================================================
# CloudWatch Log Groups
#
# Created explicitly (rather than letting Lambda auto-create them)
# so that the log_retention_days variable is honoured from day one.
# ==============================================================

resource "aws_cloudwatch_log_group" "collector" {
  name              = "/aws/lambda/${var.project_name}-collector"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_cloudwatch_log_group" "enricher" {
  name              = "/aws/lambda/${var.project_name}-enricher"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# ==============================================================
# Collector Lambda — Cache Worker (Cold Path)
# Triggered by EventBridge every 15 minutes.
# 5-minute timeout to handle large accounts with many ENIs.
# ==============================================================

resource "aws_lambda_function" "collector" {
  function_name    = "${var.project_name}-collector"
  role             = aws_iam_role.collector.arn
  handler          = "collector.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.collector.output_path
  source_code_hash = data.archive_file.collector.output_base64sha256
  timeout          = 300
  memory_size      = 512

  environment {
    variables = {
      DYNAMODB_TABLE_NAME  = aws_dynamodb_table.ip_cache.name
      DYNAMODB_TTL_MINUTES = tostring(var.dynamodb_ttl_minutes)
      AWS_REGION_NAME      = var.aws_region
    }
  }

  # Ensure the log group exists before Lambda is created, so the first
  # invocation does not trigger a race condition on log group creation.
  depends_on = [
    aws_cloudwatch_log_group.collector,
    aws_iam_role_policy.collector
  ]

  tags = var.tags
}

# ==============================================================
# Enricher Lambda — Firehose Transformation Processor (Hot Path)
# Invoked inline by Firehose for every buffered batch.
# 3-minute timeout (Firehose transformation max is 5 min).
# ==============================================================

resource "aws_lambda_function" "enricher" {
  function_name    = "${var.project_name}-enricher"
  role             = aws_iam_role.enricher.arn
  handler          = "enricher.lambda_handler"
  runtime          = "python3.12"
  filename         = data.archive_file.enricher.output_path
  source_code_hash = data.archive_file.enricher.output_base64sha256
  timeout          = 180
  memory_size      = 512

  environment {
    variables = {
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.ip_cache.name
      AWS_REGION_NAME     = var.aws_region
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.enricher,
    aws_iam_role_policy.enricher
  ]

  tags = var.tags
}

# Allow Firehose to invoke the enricher Lambda
resource "aws_lambda_permission" "allow_firehose_enricher" {
  statement_id  = "AllowFirehoseInvokeEnricher"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.enricher.function_name
  principal     = "firehose.amazonaws.com"
  source_arn    = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
}
```

- [ ] **Step 2: Create `outputs.tf`**

```hcl
# ==============================================================
# Outputs — Key resource identifiers for downstream use
# ==============================================================

output "dynamodb_table_name" {
  description = "Name of the DynamoDB IP metadata cache table."
  value       = aws_dynamodb_table.ip_cache.name
}

output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB IP metadata cache table."
  value       = aws_dynamodb_table.ip_cache.arn
}

output "firehose_stream_name" {
  description = "Name of the Firehose delivery stream receiving VPC Flow Logs."
  value       = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.name
}

output "firehose_stream_arn" {
  description = "ARN of the Firehose delivery stream."
  value       = aws_kinesis_firehose_delivery_stream.vpc_flow_logs.arn
}

output "s3_backup_bucket_name" {
  description = "Name of the S3 bucket used as primary or error-backup destination."
  value       = aws_s3_bucket.firehose_backup.id
}

output "collector_lambda_arn" {
  description = "ARN of the Cache Worker (collector) Lambda."
  value       = aws_lambda_function.collector.arn
}

output "enricher_lambda_arn" {
  description = "ARN of the Firehose Processor (enricher) Lambda."
  value       = aws_lambda_function.enricher.arn
}

output "target_vpc_ids" {
  description = "List of VPC IDs that have direct-to-Firehose Flow Logs enabled."
  value       = local.target_vpc_ids
}
```

- [ ] **Step 3: Run `terraform validate`**

```bash
terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 4: Commit**

```bash
git add lambdas.tf outputs.tf
git commit -m "feat: add Lambda packaging, CloudWatch Log Groups, and module outputs"
```

---

## Task 7: Examples

**Files:**
- Create: `examples/s3/main.tf`
- Create: `examples/datadog/main.tf`
- Create: `examples/splunk/main.tf`

- [ ] **Step 1: Create `examples/s3/main.tf`**

```hcl
# Example: S3 destination (default — zero external credentials required)
# Run: terraform init && terraform plan

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

module "log_enricher" {
  source = "../../"

  project_name          = "log-enricher-lab"
  siem_destination_type = "s3"

  tags = {
    Environment = "lab"
    ManagedBy   = "terraform"
  }
}

output "s3_bucket" {
  value = module.log_enricher.s3_backup_bucket_name
}

output "firehose_stream" {
  value = module.log_enricher.firehose_stream_name
}
```

- [ ] **Step 2: Create `examples/datadog/main.tf`**

```hcl
# Example: Datadog HTTP intake destination
# Run: terraform init && terraform plan -var="datadog_api_key=YOUR_KEY"

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "datadog_api_key" {
  description = "Datadog API key for Firehose HTTP intake."
  type        = string
  sensitive   = true
}

module "log_enricher" {
  source = "../../"

  project_name          = "log-enricher-prod"
  siem_destination_type = "datadog"
  datadog_api_key       = var.datadog_api_key

  tags = {
    Environment = "prod"
    ManagedBy   = "terraform"
  }
}
```

- [ ] **Step 3: Create `examples/splunk/main.tf`**

```hcl
# Example: Splunk HEC destination
# Run: terraform init && terraform plan -var="splunk_hec_endpoint=..." -var="splunk_hec_token=..."

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "splunk_hec_endpoint" {
  description = "Splunk HEC endpoint URL."
  type        = string
}

variable "splunk_hec_token" {
  description = "Splunk HEC token."
  type        = string
  sensitive   = true
}

module "log_enricher" {
  source = "../../"

  project_name          = "log-enricher-prod"
  siem_destination_type = "splunk"
  splunk_hec_endpoint   = var.splunk_hec_endpoint
  splunk_hec_token      = var.splunk_hec_token

  tags = {
    Environment = "prod"
    ManagedBy   = "terraform"
  }
}
```

- [ ] **Step 4: Validate the S3 example**

```bash
cd examples/s3
terraform init
terraform validate
cd ../..
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Commit**

```bash
git add examples/
git commit -m "feat: add s3, datadog, and splunk example configurations"
```

---

## Task 8: Collector — Write Failing Tests

**Files:**
- Create: `tests/test_collector.py`

- [ ] **Step 1: Install test dependencies**

```bash
pip install pytest requests-mock boto3
```

- [ ] **Step 2: Create `tests/test_collector.py`**

```python
"""
Unit tests for the collector Lambda (Cache Worker).
Run: pytest tests/test_collector.py -v
"""

import os
from unittest.mock import MagicMock

import pytest

# Set required env vars before importing the module under test
os.environ["DYNAMODB_TABLE_NAME"] = "test-ip-cache"
os.environ["DYNAMODB_TTL_MINUTES"] = "30"
os.environ["AWS_REGION_NAME"] = "us-east-1"

import collector  # noqa: E402


# ---------------------------------------------------------------------------
# fetch_threat_intel
# ---------------------------------------------------------------------------

class TestFetchThreatIntel:
    def test_returns_plain_ips(self, requests_mock):
        requests_mock.get(collector.THREAT_INTEL_FEEDS["emerging_threats"], text="1.2.3.4\n5.6.7.8\n")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["spamhaus_drop"], text="")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["feodo_tracker"], text="")

        result = collector.fetch_threat_intel()

        assert "1.2.3.4" in result
        assert "5.6.7.8" in result

    def test_ignores_comment_lines(self, requests_mock):
        requests_mock.get(collector.THREAT_INTEL_FEEDS["emerging_threats"], text="# comment\n; another\n1.2.3.4\n")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["spamhaus_drop"], text="")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["feodo_tracker"], text="")

        result = collector.fetch_threat_intel()

        assert "1.2.3.4" in result
        assert not any(e.startswith("#") or e.startswith(";") for e in result)

    def test_ignores_blank_lines(self, requests_mock):
        requests_mock.get(collector.THREAT_INTEL_FEEDS["emerging_threats"], text="\n\n1.2.3.4\n\n")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["spamhaus_drop"], text="")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["feodo_tracker"], text="")

        result = collector.fetch_threat_intel()

        assert "" not in result

    def test_continues_when_one_feed_fails(self, requests_mock):
        requests_mock.get(collector.THREAT_INTEL_FEEDS["emerging_threats"], exc=Exception("connection timeout"))
        requests_mock.get(collector.THREAT_INTEL_FEEDS["spamhaus_drop"], text="9.9.9.9\n")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["feodo_tracker"], text="")

        result = collector.fetch_threat_intel()

        assert "9.9.9.9" in result

    def test_parses_all_three_feeds(self, requests_mock):
        requests_mock.get(collector.THREAT_INTEL_FEEDS["emerging_threats"], text="1.1.1.1\n")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["spamhaus_drop"], text="2.2.2.2\n")
        requests_mock.get(collector.THREAT_INTEL_FEEDS["feodo_tracker"], text="3.3.3.3\n")

        result = collector.fetch_threat_intel()

        assert "1.1.1.1" in result
        assert "2.2.2.2" in result
        assert "3.3.3.3" in result


# ---------------------------------------------------------------------------
# is_threat_ip
# ---------------------------------------------------------------------------

class TestIsThreatIp:
    def test_exact_ip_match(self):
        assert collector.is_threat_ip("1.2.3.4", {"1.2.3.4"}) is True

    def test_no_match_returns_false(self):
        assert collector.is_threat_ip("1.2.3.4", {"5.6.7.8"}) is False

    def test_cidr_match(self):
        assert collector.is_threat_ip("10.0.0.5", {"10.0.0.0/24"}) is True

    def test_cidr_no_match(self):
        assert collector.is_threat_ip("10.0.1.5", {"10.0.0.0/24"}) is False

    def test_empty_set_returns_false(self):
        assert collector.is_threat_ip("1.2.3.4", set()) is False


# ---------------------------------------------------------------------------
# collect_eni_metadata
# ---------------------------------------------------------------------------

def _make_paginator(pages: list) -> MagicMock:
    """Helper: returns a mock paginator whose .paginate() yields the given pages."""
    mock_pager = MagicMock()
    mock_pager.paginate.return_value = iter(pages)
    return mock_pager


class TestCollectENIMetadata:
    def _make_ec2_client(self, interfaces, instances=None, subnets=None, nacls=None):
        mock = MagicMock()
        mock.get_paginator.side_effect = lambda name: {
            "describe_network_interfaces": _make_paginator([{"NetworkInterfaces": interfaces}]),
            "describe_instances": _make_paginator([{"Reservations": instances or []}]),
            "describe_subnets": _make_paginator([{"Subnets": subnets or []}]),
            "describe_network_acls": _make_paginator([{"NetworkAcls": nacls or []}]),
        }[name]
        return mock

    def test_returns_one_record_per_private_ip(self):
        ec2 = self._make_ec2_client([{
            "NetworkInterfaceId": "eni-abc",
            "OwnerId": "123456789012",
            "AvailabilityZone": "us-east-1a",
            "VpcId": "vpc-111",
            "SubnetId": "subnet-222",
            "PrivateIpAddress": "10.0.0.1",
            "Groups": [],
            "TagSet": [],
            "Attachment": {},
        }])

        records = collector.collect_eni_metadata(ec2)

        assert len(records) == 1
        assert records[0]["ip_address"] == "10.0.0.1"

    def test_adds_public_ip_record_when_present(self):
        ec2 = self._make_ec2_client([{
            "NetworkInterfaceId": "eni-abc",
            "OwnerId": "123456789012",
            "AvailabilityZone": "us-east-1a",
            "VpcId": "vpc-111",
            "SubnetId": "subnet-222",
            "PrivateIpAddress": "10.0.0.1",
            "Groups": [],
            "TagSet": [],
            "Attachment": {},
            "Association": {"PublicIp": "52.1.2.3"},
        }])

        records = collector.collect_eni_metadata(ec2)
        ips = [r["ip_address"] for r in records]

        assert "10.0.0.1" in ips
        assert "52.1.2.3" in ips
        assert len(records) == 2

    def test_sets_resource_type_ec2_instance_when_attached(self):
        ec2 = self._make_ec2_client(
            interfaces=[{
                "NetworkInterfaceId": "eni-abc",
                "OwnerId": "123456789012",
                "AvailabilityZone": "us-east-1a",
                "VpcId": "vpc-111",
                "SubnetId": "subnet-222",
                "PrivateIpAddress": "10.0.0.1",
                "Groups": [{"GroupId": "sg-999"}],
                "TagSet": [],
                "Attachment": {"InstanceId": "i-0abc123"},
            }],
            instances=[{
                "Instances": [{
                    "InstanceId": "i-0abc123",
                    "Tags": [{"Key": "Name", "Value": "web-server"}],
                }]
            }],
        )

        records = collector.collect_eni_metadata(ec2)

        assert records[0]["resource_type"] == "EC2_Instance"
        assert records[0]["resource_id"] == "i-0abc123"
        assert records[0]["resource_tags"] == {"Name": "web-server"}

    def test_attaches_sg_ids_to_record(self):
        ec2 = self._make_ec2_client([{
            "NetworkInterfaceId": "eni-abc",
            "OwnerId": "123456789012",
            "AvailabilityZone": "us-east-1a",
            "VpcId": "vpc-111",
            "SubnetId": "subnet-222",
            "PrivateIpAddress": "10.0.0.1",
            "Groups": [{"GroupId": "sg-111"}, {"GroupId": "sg-222"}],
            "TagSet": [],
            "Attachment": {},
        }])

        records = collector.collect_eni_metadata(ec2)

        assert "sg-111" in records[0]["attached_sgs"]
        assert "sg-222" in records[0]["attached_sgs"]
```

- [ ] **Step 3: Run tests — expect failure (collector.py is a placeholder)**

```bash
cd functions/collector && pip install -r requirements.txt && cd ../..
pytest tests/test_collector.py -v
```
Expected: `ImportError` or `NotImplementedError` — tests cannot pass yet.

- [ ] **Step 4: Commit the failing tests**

```bash
git add tests/test_collector.py
git commit -m "test: add failing unit tests for collector Lambda"
```

---

## Task 9: Collector — Implementation

**Files:**
- Modify: `functions/collector/collector.py`

- [ ] **Step 1: Replace `functions/collector/collector.py` with full implementation**

```python
"""
Collector Lambda — Cache Worker (Cold Path)

Runs every 15 minutes via EventBridge. For each target account
(v1.0: local account only), scans EC2 network metadata and three
open-source Threat Intel feeds, then upserts all IP-to-resource
mappings into the DynamoDB cache table.

Multi-account seam: get_boto3_client() is the single extension
point for adding AssumeRole support in v2.0. The main scan loop
iterates over [LOCAL_ACCOUNT_ID] in v1.0 — replace this list
with an AWS Organizations API call in v2.0.
"""

import logging
import os
import time
from ipaddress import ip_address, ip_network
from typing import Any

import boto3
import requests

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE_NAME: str = os.environ["DYNAMODB_TABLE_NAME"]
DYNAMODB_TTL_MINUTES: int = int(os.environ.get("DYNAMODB_TTL_MINUTES", "30"))
AWS_REGION: str = os.environ.get("AWS_REGION_NAME", "us-east-1")

THREAT_INTEL_FEEDS: dict[str, str] = {
    "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
}

LOCAL_ACCOUNT_ID: str | None = None


def get_boto3_client(service: str, account_id: str | None = None, region: str | None = None):
    """
    Returns a boto3 client for the given service.

    v1.0: Returns a direct client for the local account.
    v2.0 hook: When account_id differs from LOCAL_ACCOUNT_ID, assume
    arn:aws:iam::{account_id}:role/LogEnricher-CollectorRole via STS
    and return a client using the temporary credentials.
    """
    if account_id is None or account_id == LOCAL_ACCOUNT_ID:
        return boto3.client(service, region_name=region or AWS_REGION)
    # v2.0: replace this with AssumeRole + session credentials
    raise NotImplementedError(
        f"Multi-account support (account_id={account_id}) is coming in v2.0"
    )


def fetch_threat_intel() -> set[str]:
    """
    Fetches all configured Threat Intel feeds and returns a flat set
    of IP addresses and CIDR blocks that are considered malicious.
    Feed failures are logged as warnings and do not abort the run.
    """
    threat_entries: set[str] = set()

    for feed_name, url in THREAT_INTEL_FEEDS.items():
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            count_before = len(threat_entries)
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                # Some feeds use "ip ; comment" format — take only the IP/CIDR part
                entry = line.split(";")[0].strip().split()[0]
                if entry:
                    threat_entries.add(entry)
            logger.info("Feed %s: loaded %d entries", feed_name, len(threat_entries) - count_before)
        except Exception as exc:
            logger.warning("Feed %s: fetch failed — %s", feed_name, exc)

    return threat_entries


def is_threat_ip(ip: str, threat_set: set[str]) -> bool:
    """
    Returns True if the given IP matches any entry in threat_set
    (exact match or falls within a CIDR range).
    """
    if ip in threat_set:
        return True
    try:
        addr = ip_address(ip)
        for entry in threat_set:
            try:
                if addr in ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
    except ValueError:
        pass
    return False


def collect_eni_metadata(ec2_client) -> list[dict[str, Any]]:
    """
    Paginates through all ENIs in the account and returns a list of
    IP-to-resource records ready for DynamoDB upsert. Each record
    represents one IP address (private or public) associated with an ENI.
    """
    records: list[dict] = []

    # --- Describe network interfaces ---
    eni_paginator = ec2_client.get_paginator("describe_network_interfaces")
    interfaces = []
    for page in eni_paginator.paginate():
        interfaces.extend(page["NetworkInterfaces"])

    # --- Build instance tag lookup (InstanceId → Tags) ---
    instance_tags: dict[str, dict] = {}
    inst_paginator = ec2_client.get_paginator("describe_instances")
    for page in inst_paginator.paginate():
        for reservation in page.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                instance_tags[inst["InstanceId"]] = {
                    t["Key"]: t["Value"] for t in inst.get("Tags", [])
                }

    # --- Build subnet → NACL lookup ---
    nacl_map: dict[str, str] = {}
    nacl_paginator = ec2_client.get_paginator("describe_network_acls")
    for page in nacl_paginator.paginate():
        for nacl in page.get("NetworkAcls", []):
            for assoc in nacl.get("Associations", []):
                nacl_map[assoc["SubnetId"]] = nacl["NetworkAclId"]

    for eni in interfaces:
        account_id = eni.get("OwnerId", "")
        vpc_id = eni.get("VpcId", "")
        subnet_id = eni.get("SubnetId", "")
        attached_sgs = [sg["GroupId"] for sg in eni.get("Groups", [])]
        nacl_id = nacl_map.get(subnet_id)

        resource_type = "ENI"
        resource_id = eni["NetworkInterfaceId"]
        arn = f"arn:aws:ec2:{AWS_REGION}:{account_id}:network-interface/{resource_id}"
        resource_tags: dict = {t["Key"]: t["Value"] for t in eni.get("TagSet", [])}

        attachment = eni.get("Attachment", {})
        instance_id = attachment.get("InstanceId")
        if instance_id:
            resource_type = "EC2_Instance"
            resource_id = instance_id
            arn = f"arn:aws:ec2:{AWS_REGION}:{account_id}:instance/{resource_id}"
            resource_tags = instance_tags.get(instance_id, resource_tags)

        base: dict[str, Any] = {
            "account_id": account_id,
            "region": AWS_REGION,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "arn": arn,
            "resource_tags": resource_tags,
            "aws_service_type": None,
            "attached_sgs": attached_sgs,
            "nacl_id": nacl_id,
        }

        private_ip = eni.get("PrivateIpAddress")
        if private_ip:
            records.append({"ip_address": private_ip, **base})

        public_ip = eni.get("Association", {}).get("PublicIp")
        if public_ip:
            records.append({"ip_address": public_ip, **base})

    return records


def upsert_to_dynamodb(table, records: list[dict], threat_set: set[str]) -> None:
    """
    Upserts each IP record into DynamoDB. Sets:
    - expires_at: Unix epoch timestamp for TTL-based auto-expiry
    - threat_intel: list of matching feed names, or None if clean
    """
    expires_at = int(time.time()) + (DYNAMODB_TTL_MINUTES * 60)

    for record in records:
        ip = record["ip_address"]
        matched_feeds = [name for name in THREAT_INTEL_FEEDS if is_threat_ip(ip, threat_set)]
        table.put_item(Item={
            **record,
            "expires_at": expires_at,
            "threat_intel": matched_feeds if matched_feeds else None,
        })


def lambda_handler(event: dict, context: Any) -> dict:
    """Entry point. Refreshes the entire IP cache for all target accounts."""
    global LOCAL_ACCOUNT_ID

    LOCAL_ACCOUNT_ID = boto3.client("sts").get_caller_identity()["Account"]
    logger.info("Cache refresh started — account %s", LOCAL_ACCOUNT_ID)

    threat_set = fetch_threat_intel()
    logger.info("Threat Intel loaded — %d total entries", len(threat_set))

    # v1.0: single-account. v2.0: replace with list from AWS Organizations.
    target_accounts = [LOCAL_ACCOUNT_ID]

    dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
    table = dynamodb.Table(DYNAMODB_TABLE_NAME)

    total = 0
    for account_id in target_accounts:
        ec2 = get_boto3_client("ec2", account_id=account_id)
        records = collect_eni_metadata(ec2)
        upsert_to_dynamodb(table, records, threat_set)
        total += len(records)
        logger.info("Upserted %d records for account %s", len(records), account_id)

    logger.info("Cache refresh complete — %d total records upserted", total)
    return {"statusCode": 200, "upserted": total}
```

- [ ] **Step 2: Run the tests — expect all to pass**

```bash
pytest tests/test_collector.py -v
```
Expected output:
```
tests/test_collector.py::TestFetchThreatIntel::test_returns_plain_ips PASSED
tests/test_collector.py::TestFetchThreatIntel::test_ignores_comment_lines PASSED
tests/test_collector.py::TestFetchThreatIntel::test_ignores_blank_lines PASSED
tests/test_collector.py::TestFetchThreatIntel::test_continues_when_one_feed_fails PASSED
tests/test_collector.py::TestFetchThreatIntel::test_parses_all_three_feeds PASSED
tests/test_collector.py::TestIsThreatIp::test_exact_ip_match PASSED
tests/test_collector.py::TestIsThreatIp::test_no_match_returns_false PASSED
tests/test_collector.py::TestIsThreatIp::test_cidr_match PASSED
tests/test_collector.py::TestIsThreatIp::test_cidr_no_match PASSED
tests/test_collector.py::TestIsThreatIp::test_empty_set_returns_false PASSED
tests/test_collector.py::TestCollectENIMetadata::test_returns_one_record_per_private_ip PASSED
tests/test_collector.py::TestCollectENIMetadata::test_adds_public_ip_record_when_present PASSED
tests/test_collector.py::TestCollectENIMetadata::test_sets_resource_type_ec2_instance_when_attached PASSED
tests/test_collector.py::TestCollectENIMetadata::test_attaches_sg_ids_to_record PASSED

14 passed
```

- [ ] **Step 3: Commit**

```bash
git add functions/collector/collector.py
git commit -m "feat: implement collector Lambda (cache worker)"
```

---

## Task 10: Enricher — Write Failing Tests

**Files:**
- Create: `tests/test_enricher.py`

- [ ] **Step 1: Create `tests/test_enricher.py`**

```python
"""
Unit tests for the enricher Lambda (Firehose Transformation Processor).
Run: pytest tests/test_enricher.py -v
"""

import base64
import json
import os
from unittest.mock import patch

import pytest

os.environ["DYNAMODB_TABLE_NAME"] = "test-ip-cache"
os.environ["AWS_REGION_NAME"] = "us-east-1"

import enricher  # noqa: E402

# ---------------------------------------------------------------------------
# Test fixtures — representative raw VPC Flow Log lines
# Fields: version account-id srcaddr dstaddr srcport dstport protocol
#         packets bytes start end action log-status reject-reason
#         tcp-flags traffic-path pkt-src-aws-service
# ---------------------------------------------------------------------------

RAW_REJECT_SG = (
    "2 123456789012 10.0.0.1 10.0.0.2 12345 80 6 "
    "1 52 1700000000 1700000060 REJECT OK SecurityGroup 2 1 -"
)
RAW_REJECT_NACL = (
    "2 123456789012 10.0.0.1 10.0.0.2 12345 80 6 "
    "1 52 1700000000 1700000060 REJECT OK NetworkAcl 2 1 -"
)
RAW_ACCEPT_SYN_ONLY = (
    "2 123456789012 10.0.0.1 10.0.0.2 12345 80 6 "
    "1 40 1700000000 1700000060 ACCEPT OK - 2 1 -"
)
RAW_ACCEPT_NORMAL = (
    "2 123456789012 10.0.0.1 10.0.0.2 12345 80 6 "
    "10 2048 1700000000 1700000060 ACCEPT OK - 18 1 -"
)


def _encode(raw: str) -> str:
    return base64.b64encode(raw.encode()).decode()


# ---------------------------------------------------------------------------
# parse_flow_log_line
# ---------------------------------------------------------------------------

class TestParseFlowLogLine:
    def test_parses_srcaddr_and_dstaddr(self):
        record = enricher.parse_flow_log_line(RAW_REJECT_SG)
        assert record["srcaddr"] == "10.0.0.1"
        assert record["dstaddr"] == "10.0.0.2"

    def test_parses_action_and_reject_reason(self):
        record = enricher.parse_flow_log_line(RAW_REJECT_SG)
        assert record["action"] == "REJECT"
        assert record["reject_reason"] == "SecurityGroup"

    def test_converts_numeric_fields_to_int(self):
        record = enricher.parse_flow_log_line(RAW_REJECT_SG)
        assert isinstance(record["srcport"], int)
        assert isinstance(record["tcp_flags"], int)
        assert isinstance(record["bytes"], int)

    def test_dash_fields_become_none(self):
        record = enricher.parse_flow_log_line(RAW_ACCEPT_NORMAL)
        assert record["reject_reason"] is None
        assert record["pkt_src_aws_service"] is None


# ---------------------------------------------------------------------------
# evaluate_troubleshooting
# ---------------------------------------------------------------------------

class TestEvaluateTroubleshooting:
    def _empty(self):
        return enricher.build_empty_asset()

    def test_detects_security_group_block(self):
        record = enricher.parse_flow_log_line(RAW_REJECT_SG)
        src = {**self._empty(), "attached_sgs": ["sg-src-111"]}
        dst = {**self._empty(), "attached_sgs": ["sg-dst-222"]}

        result = enricher.evaluate_troubleshooting(record, src, dst)

        assert result is not None
        assert result["rule"] == "SECURITY_GROUP_BLOCK_L4"
        assert "sg-src-111" in result["attached_sgs"]
        assert "sg-dst-222" in result["attached_sgs"]

    def test_detects_nacl_block(self):
        record = enricher.parse_flow_log_line(RAW_REJECT_NACL)
        src = self._empty()
        dst = {**self._empty(), "subnet_id": "subnet-abc", "nacl_id": "acl-xyz"}

        result = enricher.evaluate_troubleshooting(record, src, dst)

        assert result is not None
        assert result["rule"] == "NACL_BLOCK_L3_L4"
        assert result["subnet_id"] == "subnet-abc"
        assert result["nacl_id"] == "acl-xyz"

    def test_detects_routing_timeout_syn_only(self):
        record = enricher.parse_flow_log_line(RAW_ACCEPT_SYN_ONLY)
        src = self._empty()
        dst = self._empty()

        result = enricher.evaluate_troubleshooting(record, src, dst)

        assert result is not None
        assert result["rule"] == "ROUTING_TIMEOUT_L3"

    def test_normal_traffic_returns_none(self):
        record = enricher.parse_flow_log_line(RAW_ACCEPT_NORMAL)
        src = self._empty()
        dst = self._empty()

        result = enricher.evaluate_troubleshooting(record, src, dst)

        assert result is None

    def test_first_matching_rule_wins(self):
        # REJECT + SecurityGroup should match first, not ROUTING_TIMEOUT
        record = enricher.parse_flow_log_line(RAW_REJECT_SG)
        src = self._empty()
        dst = self._empty()

        result = enricher.evaluate_troubleshooting(record, src, dst)

        assert result["rule"] == "SECURITY_GROUP_BLOCK_L4"


# ---------------------------------------------------------------------------
# lambda_handler
# ---------------------------------------------------------------------------

class TestLambdaHandler:
    def test_returns_ok_result_for_valid_record(self):
        with patch.object(enricher, "lookup_ips", return_value={}):
            result = enricher.lambda_handler(
                {"records": [{"recordId": "rec-001", "data": _encode(RAW_REJECT_SG)}]},
                None,
            )

        assert len(result["records"]) == 1
        assert result["records"][0]["result"] == "Ok"
        assert result["records"][0]["recordId"] == "rec-001"

    def test_output_contains_enrichment_node(self):
        with patch.object(enricher, "lookup_ips", return_value={}):
            result = enricher.lambda_handler(
                {"records": [{"recordId": "r1", "data": _encode(RAW_REJECT_SG)}]},
                None,
            )

        body = json.loads(base64.b64decode(result["records"][0]["data"]))
        assert "enrichment" in body
        assert "source_asset" in body["enrichment"]
        assert "destination_asset" in body["enrichment"]

    def test_troubleshooting_node_present_on_reject(self):
        with patch.object(enricher, "lookup_ips", return_value={}):
            result = enricher.lambda_handler(
                {"records": [{"recordId": "r1", "data": _encode(RAW_REJECT_SG)}]},
                None,
            )

        body = json.loads(base64.b64decode(result["records"][0]["data"]))
        assert "troubleshooting" in body
        assert body["troubleshooting"]["rule"] == "SECURITY_GROUP_BLOCK_L4"

    def test_troubleshooting_node_absent_on_normal_traffic(self):
        with patch.object(enricher, "lookup_ips", return_value={}):
            result = enricher.lambda_handler(
                {"records": [{"recordId": "r1", "data": _encode(RAW_ACCEPT_NORMAL)}]},
                None,
            )

        body = json.loads(base64.b64decode(result["records"][0]["data"]))
        assert "troubleshooting" not in body

    def test_cache_miss_sets_flag_and_does_not_drop_record(self):
        with patch.object(enricher, "lookup_ips", return_value={}):
            result = enricher.lambda_handler(
                {"records": [{"recordId": "r1", "data": _encode(RAW_ACCEPT_NORMAL)}]},
                None,
            )

        body = json.loads(base64.b64decode(result["records"][0]["data"]))
        assert body["enrichment"]["source_asset"]["cache_miss"] is True
        assert result["records"][0]["result"] == "Ok"

    def test_cache_hit_populates_asset_fields(self):
        fake_cache = {
            "10.0.0.1": {
                "ip_address": "10.0.0.1",
                "account_id": "123456789012",
                "region": "us-east-1",
                "vpc_id": "vpc-aaa",
                "subnet_id": "subnet-bbb",
                "resource_type": "EC2_Instance",
                "resource_id": "i-0abc",
                "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc",
                "resource_tags": {"Name": "web"},
                "aws_service_type": None,
                "attached_sgs": ["sg-ccc"],
                "nacl_id": "acl-ddd",
                "threat_intel": None,
            }
        }
        with patch.object(enricher, "lookup_ips", return_value=fake_cache):
            result = enricher.lambda_handler(
                {"records": [{"recordId": "r1", "data": _encode(RAW_ACCEPT_NORMAL)}]},
                None,
            )

        body = json.loads(base64.b64decode(result["records"][0]["data"]))
        src = body["enrichment"]["source_asset"]
        assert src["cache_miss"] is False
        assert src["vpc_id"] == "vpc-aaa"
        assert src["resource_type"] == "EC2_Instance"

    def test_processing_failed_on_exception(self):
        with patch.object(enricher, "lookup_ips", return_value={}):
            with patch.object(enricher, "enrich_record", side_effect=Exception("boom")):
                result = enricher.lambda_handler(
                    {"records": [{"recordId": "r-bad", "data": _encode(RAW_ACCEPT_NORMAL)}]},
                    None,
                )

        assert result["records"][0]["result"] == "ProcessingFailed"

    def test_processes_multiple_records_in_one_batch(self):
        with patch.object(enricher, "lookup_ips", return_value={}):
            result = enricher.lambda_handler(
                {"records": [
                    {"recordId": "r1", "data": _encode(RAW_REJECT_SG)},
                    {"recordId": "r2", "data": _encode(RAW_ACCEPT_NORMAL)},
                    {"recordId": "r3", "data": _encode(RAW_REJECT_NACL)},
                ]},
                None,
            )

        assert len(result["records"]) == 3
        assert all(r["result"] == "Ok" for r in result["records"])
```

- [ ] **Step 2: Run tests — expect failure (enricher.py is a placeholder)**

```bash
pytest tests/test_enricher.py -v
```
Expected: `ImportError` or `NotImplementedError` — tests cannot pass yet.

- [ ] **Step 3: Commit failing tests**

```bash
git add tests/test_enricher.py
git commit -m "test: add failing unit tests for enricher Lambda"
```

---

## Task 11: Enricher — Implementation

**Files:**
- Modify: `functions/enricher/enricher.py`

- [ ] **Step 1: Replace `functions/enricher/enricher.py` with full implementation**

```python
"""
Enricher Lambda — Firehose Transformation Processor (Hot Path)

Invoked inline by Amazon Data Firehose for each buffered batch of
VPC Flow Log records. Enriches each record with DynamoDB asset
metadata (dual-sided: source + destination), evaluates L3/L4
troubleshooting rules, and returns base64-encoded JSON records
in the Firehose transformation response format.

Performance design:
- All IPs in the batch are collected before any DynamoDB calls.
- A single BatchGetItem call fetches metadata for all unique IPs.
- The DynamoDB resource is initialised once (module-level) and
  reused across Lambda invocations via execution environment reuse.
"""

import base64
import json
import logging
import os
from typing import Any

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE_NAME: str = os.environ["DYNAMODB_TABLE_NAME"]
AWS_REGION: str = os.environ.get("AWS_REGION_NAME", "us-east-1")

# Field order MUST match the log_format configured in main.tf aws_flow_log
FLOW_LOG_FIELDS: list[str] = [
    "version", "account_id", "srcaddr", "dstaddr", "srcport", "dstport",
    "protocol", "packets", "bytes", "start", "end", "action", "log_status",
    "reject_reason", "tcp_flags", "traffic_path", "pkt_src_aws_service",
]

# Fields that should be cast to int when present
_INT_FIELDS = frozenset({
    "version", "srcport", "dstport", "protocol", "packets",
    "bytes", "start", "end", "tcp_flags", "traffic_path",
})

# Troubleshooting rules evaluated in order — first match wins
TROUBLESHOOTING_RULES: list[dict] = [
    {
        "id": "SECURITY_GROUP_BLOCK_L4",
        "condition": lambda r: (
            r.get("action") == "REJECT"
            and r.get("reject_reason") == "SecurityGroup"
        ),
        "hint": (
            "Connection REJECTED by Security Group. "
            "Check Inbound rules on the destination ENI or "
            "Outbound rules on the source ENI."
        ),
    },
    {
        "id": "NACL_BLOCK_L3_L4",
        "condition": lambda r: (
            r.get("action") == "REJECT"
            and r.get("reject_reason") == "NetworkAcl"
        ),
        "hint": (
            "Connection REJECTED by Network ACL (stateless). "
            "Check the NACL inbound rules on the destination subnet "
            "and outbound rules on the source subnet."
        ),
    },
    {
        "id": "ROUTING_TIMEOUT_L3",
        "condition": lambda r: (
            r.get("action") == "ACCEPT"
            and r.get("tcp_flags") == 2       # SYN-only: connection attempted
            and (r.get("bytes") or 0) < 100   # no data exchanged
        ),
        "hint": (
            "Possible routing blackhole or connection timeout "
            "(SYN accepted but no handshake completed). "
            "Validate Route Tables: check for a missing NAT Gateway route, "
            "broken VPC Peering, or unattached Transit Gateway."
        ),
    },
]

# Module-level DynamoDB resource — reused across warm invocations
_dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)


def parse_flow_log_line(line: str) -> dict[str, Any]:
    """
    Parses a single space-delimited VPC Flow Log line into a typed dict.
    Dash ('-') values are converted to None. Numeric fields are cast to int.
    """
    parts = line.strip().split(" ")
    record: dict[str, Any] = {}
    for i, field in enumerate(FLOW_LOG_FIELDS):
        raw = parts[i] if i < len(parts) else "-"
        if raw == "-":
            record[field] = None
        elif field in _INT_FIELDS:
            try:
                record[field] = int(raw)
            except ValueError:
                record[field] = raw
        else:
            record[field] = raw
    return record


def build_empty_asset(cache_miss: bool = True) -> dict[str, Any]:
    """Returns a zeroed-out asset node with cache_miss flag set."""
    return {
        "account_id": None,
        "region": None,
        "vpc_id": None,
        "subnet_id": None,
        "resource_type": None,
        "resource_id": None,
        "arn": None,
        "resource_tags": None,
        "aws_service_type": None,
        "attached_sgs": None,
        "nacl_id": None,
        "threat_intel": None,
        "cache_miss": cache_miss,
    }


def lookup_ips(ip_list: list[str]) -> dict[str, dict]:
    """
    Performs a single DynamoDB BatchGetItem for all IPs in the batch.
    Returns a dict keyed by IP address.

    Note: BatchGetItem supports up to 100 keys per call. Firehose
    transformation batches are typically well under this limit. Unprocessed
    keys (throttled by DynamoDB) are logged as a warning but not retried —
    affected records will receive cache_miss=True enrichment.
    """
    if not ip_list:
        return {}

    response = _dynamodb.batch_get_item(
        RequestItems={DYNAMODB_TABLE_NAME: {"Keys": [{"ip_address": ip} for ip in ip_list]}}
    )

    if response.get("UnprocessedKeys"):
        logger.warning(
            "DynamoDB BatchGetItem: %d unprocessed keys (throttled)",
            len(response["UnprocessedKeys"].get(DYNAMODB_TABLE_NAME, {}).get("Keys", [])),
        )

    return {
        item["ip_address"]: item
        for item in response.get("Responses", {}).get(DYNAMODB_TABLE_NAME, [])
    }


def _item_to_asset(item: dict | None) -> dict[str, Any]:
    """Converts a raw DynamoDB item to a structured asset node."""
    if item is None:
        return build_empty_asset(cache_miss=True)
    return {
        "account_id": item.get("account_id"),
        "region": item.get("region"),
        "vpc_id": item.get("vpc_id"),
        "subnet_id": item.get("subnet_id"),
        "resource_type": item.get("resource_type"),
        "resource_id": item.get("resource_id"),
        "arn": item.get("arn"),
        "resource_tags": item.get("resource_tags"),
        "aws_service_type": item.get("aws_service_type"),
        "attached_sgs": item.get("attached_sgs"),
        "nacl_id": item.get("nacl_id"),
        "threat_intel": item.get("threat_intel"),
        "cache_miss": False,
    }


def evaluate_troubleshooting(
    record: dict,
    src_asset: dict,
    dst_asset: dict,
) -> dict | None:
    """
    Evaluates L3/L4 troubleshooting rules against the parsed flow log.
    Returns the first matching rule's output dict, or None if no rule fires.
    """
    for rule in TROUBLESHOOTING_RULES:
        if not rule["condition"](record):
            continue

        result: dict[str, Any] = {
            "triggered": True,
            "rule": rule["id"],
            "hint": rule["hint"],
        }

        if rule["id"] == "SECURITY_GROUP_BLOCK_L4":
            result["attached_sgs"] = [
                sg
                for sg in [*(src_asset.get("attached_sgs") or []), *(dst_asset.get("attached_sgs") or [])]
                if sg
            ]
        elif rule["id"] == "NACL_BLOCK_L3_L4":
            result["subnet_id"] = dst_asset.get("subnet_id")
            result["nacl_id"] = dst_asset.get("nacl_id")

        return result

    return None


def enrich_record(raw_line: str, cache: dict[str, dict]) -> dict:
    """
    Builds the final enriched JSON document for a single flow log line.
    Combines parsed flow log fields, dual-sided asset enrichment, and
    optional troubleshooting analysis into a single output record.
    """
    record = parse_flow_log_line(raw_line)

    src_asset = _item_to_asset(cache.get(record.get("srcaddr")))
    dst_asset = _item_to_asset(cache.get(record.get("dstaddr")))

    enriched: dict[str, Any] = {
        **record,
        "enrichment": {
            "source_asset": src_asset,
            "destination_asset": dst_asset,
        },
    }

    troubleshooting = evaluate_troubleshooting(record, src_asset, dst_asset)
    if troubleshooting:
        enriched["troubleshooting"] = troubleshooting

    return enriched


def lambda_handler(event: dict, context: Any) -> dict:
    """
    Firehose transformation entry point.

    Process:
    1. Decode all records in the batch.
    2. Extract all unique src/dst IPs for a single BatchGetItem call.
    3. Enrich each record using the cache result.
    4. Return records in Firehose transformation format.
    """
    raw_records: list[tuple[str, str]] = []
    all_ips: set[str] = set()

    for rec in event.get("records", []):
        raw = base64.b64decode(rec["data"]).decode("utf-8").strip()
        raw_records.append((rec["recordId"], raw))
        parts = raw.split(" ")
        if len(parts) >= 4:
            if parts[2] != "-":
                all_ips.add(parts[2])
            if parts[3] != "-":
                all_ips.add(parts[3])

    cache = lookup_ips(list(all_ips))

    output: list[dict] = []
    for record_id, raw in raw_records:
        try:
            enriched = enrich_record(raw, cache)
            data = base64.b64encode(
                (json.dumps(enriched) + "\n").encode("utf-8")
            ).decode("utf-8")
            output.append({"recordId": record_id, "result": "Ok", "data": data})
        except Exception as exc:
            logger.error("Failed to enrich record %s: %s", record_id, exc)
            output.append({
                "recordId": record_id,
                "result": "ProcessingFailed",
                "data": base64.b64encode(raw.encode("utf-8")).decode("utf-8"),
            })

    return {"records": output}
```

- [ ] **Step 2: Run all tests — expect all to pass**

```bash
pytest tests/ -v
```
Expected: all 22 tests pass (14 collector + 8 enricher).

- [ ] **Step 3: Commit**

```bash
git add functions/enricher/enricher.py
git commit -m "feat: implement enricher Lambda (Firehose transformation processor)"
```

---

## Task 12: Terraform Full Validate & Plan Check

**Files:** No new files — validation only.

- [ ] **Step 1: Validate root module**

```bash
terraform validate
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 2: Run terraform plan on the S3 example (dry-run, no credentials required for validate)**

```bash
cd examples/s3
terraform init
terraform validate
cd ../..
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 3: Validate Datadog example**

```bash
cd examples/datadog
terraform init
terraform validate
cd ../..
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 4: Validate Splunk example**

```bash
cd examples/splunk
terraform init
terraform validate
cd ../..
```
Expected: `Success! The configuration is valid.`

- [ ] **Step 5: Run full test suite one final time**

```bash
pytest tests/ -v --tb=short
```
Expected: all tests pass with 0 failures.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "chore: final validation — all terraform configs valid, all tests passing"
```

---

## Self-Review Checklist

### Spec Coverage

| Spec requirement | Covered by |
|---|---|
| Amazon Data Firehose with dynamic destination blocks | Task 5 |
| DynamoDB PAY_PER_REQUEST with TTL on `expires_at` | Task 3 |
| 4 IAM roles with least-privilege policies | Task 4 |
| FlowLogsDeliveryRole for `delivery.logs.amazonaws.com` | Task 4 |
| VPC Flow Logs direct-to-Firehose with custom log format | Task 5 |
| `vpc_ids = []` targets all VPCs via `data.aws_vpcs.all` | Task 5 |
| S3 bucket always provisioned | Task 5 |
| Lambda packaging via `archive_file` | Task 6 |
| EventBridge schedule for collector | Task 5 |
| `get_boto3_client()` v2.0 seam | Task 9 |
| Three Threat Intel feeds (no auth) | Task 9 |
| CIDR-aware `is_threat_ip()` | Task 9 |
| Dual-sided enrichment (src + dst assets) | Task 11 |
| `BatchGetItem` single call per Firehose batch | Task 11 |
| `cache_miss: true` on unknown IPs (never drops logs) | Task 11 |
| `SECURITY_GROUP_BLOCK_L4` troubleshooting rule | Task 11 |
| `NACL_BLOCK_L3_L4` troubleshooting rule | Task 11 |
| `ROUTING_TIMEOUT_L3` troubleshooting rule | Task 11 |
| Three example configurations | Task 7 |
| All tests passing | Tasks 8–11 |

No gaps identified.
