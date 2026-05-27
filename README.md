# terraform-aws-log-enricher

![Terraform](https://img.shields.io/badge/Terraform-%3E%3D1.5-7B42BC?logo=terraform)
![AWS Provider](https://img.shields.io/badge/AWS_Provider-~%3E5.0-FF9900?logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-32%20passing-brightgreen)

**A production-grade, 100% serverless AWS Terraform module that enriches VPC Flow Logs in real-time with L3/L4 network topology, resource metadata, and open-source Threat Intel — then delivers structured JSON to S3, Datadog, or Splunk.**

Zero servers. Zero agents. One `terraform apply`.

---

## The Problem

VPC Flow Logs are indispensable — but raw, they're nearly unusable for rapid troubleshooting or SOC triage.

A typical raw flow log line looks like this:

```
2 123456789012 10.0.1.5 10.0.2.10 443 8080 6 12 1024 1700000000 1700000060 REJECT OK SecurityGroup 2 1 -
```

That line tells you *something* was rejected. It does not tell you:

- **Which EC2 instance or load balancer** is at `10.0.1.5`?
- **Which Security Group rule** caused the rejection?
- **Is `10.0.2.10` a known bad actor** on any threat intel list?
- **Is this a routing problem** (SYN accepted but no handshake) or an access control problem?

Without answers to these questions, a network engineer spends 15–30 minutes cross-referencing the AWS Console. A SOC analyst may not even know where to start. At scale, this friction compounds into hours of wasted investigation time per day.

---

## The Solution

`terraform-aws-log-enricher` automatically answers those questions for every flow log record, in real-time, before the log reaches your SIEM.

**What gets added to each record:**

| Enrichment | How |
|---|---|
| EC2 instance ID, ARN, and tags for the source IP | DynamoDB cache populated every 15 min |
| EC2 instance ID, ARN, and tags for the destination IP | Same cache, dual-sided lookup |
| Attached Security Group IDs | Stored alongside the IP in the cache |
| VPC, Subnet, and NACL identifiers | Derived from ENI metadata |
| Threat Intel match (3 open-source feeds) | Merged into the cache entry at collection time |
| L3/L4 troubleshooting hint | Evaluated inline per record, zero latency |

**Troubleshooting rules built in:**

| Rule | Trigger | Hint |
|---|---|---|
| `SECURITY_GROUP_BLOCK_L4` | `REJECT` + reason = `SecurityGroup` | Lists the SGs attached to both sides |
| `NACL_BLOCK_L3_L4` | `REJECT` + reason = `NetworkAcl` | Identifies the subnet and NACL to inspect |
| `ROUTING_TIMEOUT_L3` | `ACCEPT` + SYN-only + bytes < 100 | Points to Route Tables, NAT GW, VPC Peering |

**Threat Intel feeds (no API keys, no cost):**
- [Emerging Threats](https://rules.emergingthreats.net/) — compromised IPs
- [Spamhaus DROP](https://www.spamhaus.org/drop/) — hijacked CIDRs
- [Feodo Tracker](https://feodotracker.abuse.ch/) — C2 / botnet IPs

---

## Architecture

```
┌─────────────────────────────── Cold Path (every 15 min) ───────────────────────────────┐
│                                                                                         │
│   EventBridge Rule ──► Collector Lambda                                                 │
│   (rate 15 min)         │                                                               │
│                         ├── ec2:DescribeNetworkInterfaces                               │
│                         ├── ec2:DescribeInstances                                       │
│                         ├── ec2:DescribeSubnets / DescribeNetworkAcls                   │
│                         ├── Fetch Threat Intel (3 HTTPS feeds, no auth)                 │
│                         └── DynamoDB BatchWrite (hash key: ip_address, TTL: 30 min)    │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────── Hot Path (real-time) ───────────────────────────────────┐
│                                                                                         │
│   VPC Flow Logs ──► Amazon Data Firehose ──► Enricher Lambda (transformation)          │
│   (all VPCs)         (direct delivery,        │                                         │
│                       no Kinesis stream)       ├── BatchGetItem (src IP + dst IP)       │
│                                                ├── Assemble enrichment{} node           │
│                                                ├── Evaluate troubleshooting{} rules     │
│                                                └── Return base64-encoded JSON           │
│                                                                                         │
│                                          Firehose ──► S3 (default)                     │
│                                                   ──► Datadog HTTP intake               │
│                                                   ──► Splunk HEC                        │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

┌──────────────── AWS Resources Provisioned ─────────────────┐
│  DynamoDB table      PAY_PER_REQUEST, TTL on expires_at     │
│  2 Lambda functions  Python 3.12, 512 MB, least-privilege   │
│  Firehose stream     Dynamic blocks: S3 / Datadog / Splunk  │
│  S3 bucket           Always provisioned, SSE-AES256         │
│  4 IAM roles         Collector, Enricher, FlowLogs, Firehose│
│  EventBridge rule    Configurable schedule (default 15 min) │
│  VPC Flow Logs       For-each over all target VPCs          │
└────────────────────────────────────────────────────────────┘
```

**Why direct-to-Firehose (no Kinesis Data Stream)?**
VPC Flow Logs support delivering directly to a Firehose delivery stream. This eliminates the Kinesis Data Stream tier entirely — fewer moving parts, lower latency, lower cost.

**Why DynamoDB for the cache?**
The enricher Lambda is invoked inline by Firehose on every buffer flush. A DynamoDB `BatchGetItem` call completes in single-digit milliseconds. The collector Lambda pre-warms the cache every 15 minutes, so the hot path never calls the EC2 API directly.

---

## Quick Start — S3 Destination (Zero Credentials Required)

The default configuration writes enriched logs to an S3 bucket in your account. No Datadog or Splunk account needed.

### Prerequisites

- [Terraform](https://www.terraform.io/downloads) ≥ 1.5
- AWS CLI configured with credentials that can create the required resources
- An AWS account with at least one VPC

### Deploy

```bash
# 1. Clone the repository
git clone https://github.com/your-org/terraform-aws-log-enricher.git
cd terraform-aws-log-enricher/examples/s3

# 2. Initialise Terraform
terraform init

# 3. Review what will be created
terraform plan

# 4. Apply
terraform apply
```

Terraform will provision all resources and output the key identifiers:

```
Outputs:

s3_backup_bucket_name  = "log-enricher-lab-firehose-123456789012"
firehose_stream_name   = "log-enricher-lab-vpc-flow-logs"
collector_lambda_arn   = "arn:aws:lambda:us-east-1:123456789012:function:log-enricher-lab-collector"
enricher_lambda_arn    = "arn:aws:lambda:us-east-1:123456789012:function:log-enricher-lab-enricher"
target_vpc_ids         = ["vpc-0abc123", "vpc-0def456"]
```

Within 15 minutes, the collector Lambda fires for the first time and the cache is warm. Enriched JSON records begin arriving in S3 on the next Firehose flush (default: 60 seconds or 1 MB, whichever comes first).

### Using as a Terraform Module (Recommended)

```hcl
module "log_enricher" {
  source = "github.com/your-org/terraform-aws-log-enricher"

  project_name          = "log-enricher"
  siem_destination_type = "s3"

  # Optional: target specific VPCs instead of all VPCs in the account
  vpc_ids = ["vpc-0abc123", "vpc-0def456"]

  tags = {
    Environment = "prod"
    Team        = "platform"
    ManagedBy   = "terraform"
  }
}
```

---

## Input Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `aws_region` | `string` | `"us-east-1"` | Deployment region |
| `project_name` | `string` | `"log-enricher"` | Resource name prefix |
| `vpc_ids` | `list(string)` | `[]` | Target VPCs. Empty = all VPCs in the account |
| `siem_destination_type` | `string` | `"s3"` | `s3` / `datadog` / `splunk` |
| `datadog_api_key` | `string` | `""` | Required when destination is `datadog` (sensitive) |
| `splunk_hec_endpoint` | `string` | `""` | Required when destination is `splunk` |
| `splunk_hec_token` | `string` | `""` | Required when destination is `splunk` (sensitive) |
| `collector_schedule` | `string` | `"rate(15 minutes)"` | EventBridge schedule for cache refresh |
| `dynamodb_ttl_minutes` | `number` | `30` | Cache entry lifetime in minutes |
| `firehose_buffer_size_mb` | `number` | `1` | Firehose flush threshold in MB (1–128) |
| `firehose_buffer_interval_sec` | `number` | `60` | Firehose flush interval in seconds (60–900) |
| `log_retention_days` | `number` | `14` | CloudWatch Logs retention |
| `tags` | `map(string)` | `{}` | Tags applied to all resources |

---

## Outputs

| Output | Description |
|---|---|
| `dynamodb_table_name` | Name of the IP metadata cache table |
| `dynamodb_table_arn` | ARN of the DynamoDB table |
| `firehose_stream_name` | Name of the Firehose delivery stream |
| `firehose_stream_arn` | ARN of the Firehose stream |
| `s3_backup_bucket_name` | S3 bucket name (primary or error-backup) |
| `collector_lambda_arn` | ARN of the Cache Worker Lambda |
| `enricher_lambda_arn` | ARN of the Firehose Processor Lambda |
| `target_vpc_ids` | List of VPCs with Flow Logs enabled |

---

## SIEM Integrations

### Datadog

```hcl
module "log_enricher" {
  source = "github.com/your-org/terraform-aws-log-enricher"

  siem_destination_type = "datadog"
  datadog_api_key       = var.datadog_api_key   # pass via TF_VAR or secrets manager
}
```

Firehose delivers to the Datadog HTTP intake endpoint (`aws-kinesis-http-intake.logs.datadoghq.com`). Failed records fall back to the S3 bucket automatically — the bucket is always provisioned regardless of destination type.

### Splunk

```hcl
module "log_enricher" {
  source = "github.com/your-org/terraform-aws-log-enricher"

  siem_destination_type = "splunk"
  splunk_hec_endpoint   = "https://http-inputs-myorg.splunkcloud.com"
  splunk_hec_token      = var.splunk_hec_token
}
```

Firehose delivers to the Splunk HEC endpoint using the `Event` type. Undeliverable records are stored in S3 under `errors/` with a Hive-compatible prefix for easy Athena querying.

---

## Enriched Log Output

Every record delivered to your SIEM has this structure. The raw flow log fields are preserved at the top level and two new nodes are appended: `enrichment` and `troubleshooting`.

```json
{
  "version": 2,
  "account_id": "123456789012",
  "srcaddr": "10.0.1.5",
  "dstaddr": "10.0.2.10",
  "srcport": 443,
  "dstport": 8080,
  "protocol": 6,
  "packets": 12,
  "bytes": 1024,
  "start": 1700000000,
  "end": 1700000060,
  "action": "REJECT",
  "log_status": "OK",
  "reject_reason": "SecurityGroup",
  "tcp_flags": 2,
  "traffic_path": 1,
  "pkt_src_aws_service": null,

  "enrichment": {
    "source_asset": {
      "account_id": "123456789012",
      "region": "us-east-1",
      "vpc_id": "vpc-abc123",
      "subnet_id": "subnet-def456",
      "resource_type": "EC2_Instance",
      "resource_id": "i-0abc123def456",
      "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456",
      "resource_tags": { "Environment": "prod", "Team": "backend" },
      "attached_sgs": ["sg-111aaa", "sg-222bbb"],
      "threat_intel": null,
      "cache_miss": false
    },
    "destination_asset": {
      "account_id": "123456789012",
      "region": "us-east-1",
      "vpc_id": "vpc-abc123",
      "subnet_id": "subnet-ghi789",
      "resource_type": "EC2_Instance",
      "resource_id": "i-0xyz789",
      "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0xyz789",
      "resource_tags": { "Environment": "prod", "App": "api" },
      "attached_sgs": ["sg-333ccc"],
      "threat_intel": null,
      "cache_miss": false
    }
  },

  "troubleshooting": {
    "triggered": true,
    "rule": "SECURITY_GROUP_BLOCK_L4",
    "attached_sgs": ["sg-111aaa", "sg-222bbb", "sg-333ccc"],
    "hint": "Connection REJECTED by Security Group. Check Inbound rules on the destination ENI or Outbound rules on the source ENI."
  }
}
```

**Cache miss behaviour:** If an IP is not in the DynamoDB cache (external IP, or the collector has not run yet), the asset node is populated with `cache_miss: true` and all other fields set to `null`. The record is **never dropped** — it is always delivered to the SIEM with whatever context is available.

---

## IAM Permissions

The module creates four least-privilege IAM roles. No existing roles are modified.

| Role | Trusted By | Permissions |
|---|---|---|
| `CollectorRole` | `lambda.amazonaws.com` | EC2 Describe*, DynamoDB PutItem/UpdateItem on the cache table |
| `EnricherRole` | `lambda.amazonaws.com` | DynamoDB BatchGetItem on the cache table only |
| `FlowLogsDeliveryRole` | `delivery.logs.amazonaws.com` | Firehose PutRecord on the stream ARN (source-account condition) |
| `FirehoseRole` | `firehose.amazonaws.com` | S3 write on the backup bucket, Lambda InvokeFunction on the enricher |

The `FlowLogsDeliveryRole` includes an `aws:SourceAccount` confused-deputy guard on the trust policy. Without this role, `aws_flow_log` resources are created successfully by Terraform but logs silently fail to deliver — a common pitfall this module handles automatically.

---

## Cost Estimate

For a typical production account with moderate traffic:

| Resource | Billing model | Typical cost |
|---|---|---|
| Collector Lambda | Per invocation (once per 15 min) | < $0.01 / month |
| Enricher Lambda | Per GB-second of transformation | Depends on flow log volume |
| DynamoDB | PAY_PER_REQUEST + minimal storage | < $1 / month for most accounts |
| Firehose | $0.029 per GB ingested | Depends on flow log volume |
| S3 | Per GB stored + requests | Depends on retention and volume |

The dominant cost at scale is Firehose ingestion. The enricher Lambda adds no Firehose surcharge — transformation processing is included in the standard Firehose price.

---

## Roadmap

| Version | Scope |
|---|---|
| **v1.0** *(current)* | Single-account, S3 / Datadog / Splunk destinations, 3 open-source TI feeds |
| **v2.0** *(planned)* | Multi-account via AssumeRole loop, AWS Organizations discovery |
| **v2.x** *(planned)* | IPv6 flow log fields, API-based TI (AbuseIPDB), CloudWatch dashboard |

The Python code already contains a `get_boto3_client()` seam in the collector Lambda designed to accept a future `AssumeRole` implementation without a full rewrite.

---

## Development

```bash
# Install test dependencies
pip install pytest requests-mock boto3

# Run the full test suite (32 tests)
pytest tests/ -v

# Validate all Terraform configurations
terraform validate
cd examples/s3 && terraform validate && cd ../..

# Format Terraform
terraform fmt -recursive
```

See [CLAUDE.md](CLAUDE.md) for full coding standards and architectural guidelines enforced for all contributors and AI coding assistants.

---

## License

MIT — see [LICENSE](LICENSE) for details.
