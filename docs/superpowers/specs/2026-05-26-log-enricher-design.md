# Design Spec: Serverless Network Log Enricher & Troubleshooting Pipeline
**Version:** 1.0.0  
**Date:** 2026-05-26  
**Scope:** Single-account AWS deployment, open-source Terraform module

---

## 1. Objective

Build a production-grade, 100% AWS-native, serverless infrastructure module (Terraform + Python 3.12+) that:

- Collects VPC Flow Logs in real-time within a single AWS account
- Enriches them with L3/L4 network topology, resource metadata, and open-source Threat Intel
- Outputs a standardized JSON schema to a configurable SIEM destination (S3, Datadog, or Splunk)
- Serves both Security (SOC) and Operations (DevOps/SRE) teams for network troubleshooting

**v2.0 multi-account extension is explicitly out of scope** but the Python code must expose clean seams for a future `AssumeRole` loop without a full rewrite.

---

## 2. Repository Structure

```
terraform-aws-log-enricher/
├── main.tf                   # Firehose stream + VPC Flow Logs + S3 backup bucket
├── variables.tf              # All input variables
├── outputs.tf                # Key resource ARNs/names
├── dynamodb.tf               # Cache table with TTL
├── iam.tf                    # Least-privilege IAM roles
├── lambdas.tf                # Lambda resources, packaging, env vars, Log Groups
│
├── functions/
│   ├── collector/
│   │   ├── collector.py      # Cold path: cache worker
│   │   └── requirements.txt
│   └── enricher/
│       ├── enricher.py       # Hot path: Firehose transformation processor
│       └── requirements.txt
│
└── examples/
    ├── s3/main.tf            # Default — zero external credentials required
    ├── datadog/main.tf
    └── splunk/main.tf
```

---

## 3. Architecture

### 3.1 Cold Path — Cache Worker (runs every 15 minutes)

```
EventBridge Rule (rate 15 min)
    └── collector Lambda
            ├── ec2:DescribeNetworkInterfaces
            ├── ec2:DescribeInstances
            ├── ec2:DescribeSubnets
            ├── ec2:DescribeNetworkAcls
            ├── Fetch Threat Intel feeds (3 sources, HTTPS, no auth)
            └── DynamoDB Upsert (hash key: ip_address, TTL: now + 30 min)
```

**Threat Intel feeds (no API key required):**
- Emerging Threats compromised IPs: `https://rules.emergingthreats.net/blockrules/compromised-ips.txt`
- Spamhaus DROP (hijacked CIDRs): `https://www.spamhaus.org/drop/drop.txt`
- Feodo Tracker C2/botnet IPs: `https://feodotracker.abuse.ch/downloads/ipblocklist.txt`

Each feed is fetched, parsed into a set of IPs/CIDRs, and stored as a `threat_intel` attribute on each matching DynamoDB item. Non-matching IPs get `threat_intel: null`.

### 3.2 Hot Path — Real-Time Pipeline

```
VPC Flow Logs (direct-to-Firehose, custom log format)
    └── Amazon Data Firehose
            ├── enricher Lambda (transformation processor)
            │       ├── Parse raw space-delimited flow log line
            │       ├── BatchGetItem (src IP + dst IP in one call)
            │       ├── Assemble enrichment{} node (dual-sided)
            │       ├── Evaluate troubleshooting{} node (L3/L4 rules)
            │       └── Return base64-encoded JSON to Firehose
            │
            └── Destination:
                    ├── S3 bucket (default)
                    ├── Datadog HTTP intake (optional)
                    └── Splunk HEC (optional)
```

**Firehose buffer defaults:** 1 MB or 60 seconds (whichever comes first).  
**S3 backup bucket:** Always provisioned regardless of primary SIEM — Firehose requires it for failed-event storage.

**VPC Flow Log custom format:**
```
${version} ${account-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport}
${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}
${reject-reason} ${tcp-flags} ${traffic-path} ${pkt-src-aws-service}
```

---

## 4. Terraform Variables

| Variable | Type | Default | Description |
|---|---|---|---|
| `aws_region` | string | `"us-east-1"` | Deployment region |
| `project_name` | string | `"log-enricher"` | Resource name prefix |
| `vpc_ids` | list(string) | `[]` | Target VPCs. Empty = all VPCs in account (via `data "aws_vpcs"`) |
| `siem_destination_type` | string | `"s3"` | `s3` / `datadog` / `splunk` |
| `datadog_api_key` | string | `""` | Required when `siem_destination_type = "datadog"` |
| `splunk_hec_endpoint` | string | `""` | Required when `siem_destination_type = "splunk"` |
| `splunk_hec_token` | string | `""` | Required when `siem_destination_type = "splunk"` |
| `collector_schedule` | string | `"rate(15 minutes)"` | EventBridge schedule expression |
| `dynamodb_ttl_minutes` | number | `30` | Cache entry lifetime in minutes |
| `firehose_buffer_size_mb` | number | `1` | Firehose buffer size (1–128 MB) |
| `firehose_buffer_interval_sec` | number | `60` | Firehose buffer interval (60–900 sec) |
| `log_retention_days` | number | `14` | CloudWatch Logs retention |
| `tags` | map(string) | `{}` | Tags applied to all resources |

**VPC discovery logic (`main.tf` locals):**
```hcl
data "aws_vpcs" "all" {}

locals {
  target_vpc_ids = length(var.vpc_ids) > 0 ? var.vpc_ids : data.aws_vpcs.all.ids
}
```

---

## 5. Terraform Resources

### `dynamodb.tf`
- `aws_dynamodb_table` — billing mode `PAY_PER_REQUEST`, hash key `ip_address` (String), TTL attribute `expires_at`

### `iam.tf`
- `aws_iam_role` + `aws_iam_role_policy` for **CollectorRole**:
  - `ec2:DescribeNetworkInterfaces`, `ec2:DescribeInstances`, `ec2:DescribeSubnets`, `ec2:DescribeNetworkAcls`
  - `dynamodb:PutItem`, `dynamodb:UpdateItem`
  - `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`
- `aws_iam_role` + `aws_iam_role_policy` for **EnricherRole**:
  - `dynamodb:BatchGetItem`
  - `firehose:PutRecord`, `firehose:PutRecordBatch`
  - `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`
- `aws_iam_role` + `aws_iam_role_policy` for **FlowLogsDeliveryRole** (trusted by `delivery.logs.amazonaws.com`):
  - `firehose:PutRecord`, `firehose:PutRecordBatch` on the Firehose stream ARN
  - This role is passed via `iam_role_arn` on every `aws_flow_log` resource. Without it, VPC Flow Logs will be enabled but silently fail to deliver.

### `lambdas.tf`
- `data "archive_file"` for collector and enricher (zip at plan time from `functions/`)
- `aws_lambda_function` for each (Python 3.12, 512 MB memory, 5 min timeout for collector / 3 min for enricher)
- `aws_cloudwatch_log_group` for each with `log_retention_days` retention
- `aws_lambda_permission` for Firehose to invoke enricher

### `main.tf`
- `aws_s3_bucket` — always provisioned (primary destination when `siem_destination_type = "s3"`, backup bucket for all other modes)
- `aws_kinesis_firehose_delivery_stream` — with `dynamic` blocks for three destination types
- `aws_flow_log` — `for_each` over `local.target_vpc_ids`, `log_destination_type = "kinesis-data-firehose"`, custom log format, IAM role for Flow Logs service to write to Firehose

---

## 6. Output JSON Schema

Every enriched log delivered to the SIEM has this top-level structure:

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
      "resource_id": "i-0abc123",
      "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
      "resource_tags": {"Environment": "prod", "Owner": "sre-team"},
      "aws_service_type": null,
      "threat_intel": null,
      "cache_miss": false
    },
    "destination_asset": {
      "account_id": "123456789012",
      "region": "us-east-1",
      "vpc_id": "vpc-abc123",
      "subnet_id": "subnet-ghi789",
      "resource_type": "Application_Load_Balancer",
      "resource_id": "arn:aws:elasticloadbalancing:...",
      "arn": "arn:aws:elasticloadbalancing:...",
      "resource_tags": {"Environment": "prod", "App": "api-gateway"},
      "aws_service_type": null,
      "threat_intel": null,
      "cache_miss": false
    }
  },
  "troubleshooting": {
    "triggered": true,
    "rule": "SECURITY_GROUP_BLOCK_L4",
    "attached_sgs": ["sg-111aaa", "sg-222bbb"],
    "hint": "Connection REJECTED by Security Group. Check Inbound rules on destination ENI or Outbound rules on source ENI."
  }
}
```

**Cache miss behavior:** If an IP is not found in DynamoDB (external IP, or cache hasn't run yet), the asset object is populated with `cache_miss: true` and all other fields set to `null`. The log is never dropped.

---

## 7. Troubleshooting Rules

| Rule ID | Condition | Output |
|---|---|---|
| `SECURITY_GROUP_BLOCK_L4` | `action == REJECT` AND `reject_reason == SecurityGroup` | List `attached_sgs` from cache; hint to check SG inbound/outbound rules |
| `NACL_BLOCK_L3_L4` | `action == REJECT` AND `reject_reason == NetworkAcl` | Map to `subnet_id`; hint to check stateless NACL rules for that subnet |
| `ROUTING_TIMEOUT_L3` | `action == ACCEPT` AND `tcp_flags == 2` AND `bytes < 100` | Flag as routing timeout; hint to validate Route Tables (NAT GW, VPC Peering, TGW) |

Only one rule fires per log record (first match wins). If no rule matches, `troubleshooting` is omitted from the output.

---

## 8. Python Code Structure (multi-account seams)

Both Lambda functions use a `get_boto3_client(service, account_id=None, region=None)` helper:

```python
def get_boto3_client(service, account_id=None, region=None):
    """
    Returns a boto3 client. In v1.0 (single-account), returns a direct client.
    In v2.0, when account_id differs from the local account, will AssumeRole first.
    """
    if account_id is None or account_id == LOCAL_ACCOUNT_ID:
        return boto3.client(service, region_name=region or AWS_REGION)
    # v2.0 hook: AssumeRole logic goes here
    raise NotImplementedError("Multi-account support coming in v2.0")
```

The collector's main scan loop iterates over `[LOCAL_ACCOUNT_ID]` in v1.0 — in v2.0 this list comes from AWS Organizations.

---

## 9. Out of Scope (v1.0)

- Multi-account / cross-account AssumeRole
- AWS Organizations-wide deployment via StackSets
- VPC Flow Logs IPv6 fields
- API-based Threat Intel (AbuseIPDB, VirusTotal)
- Terraform remote state configuration (left to the consumer)
- CloudWatch Dashboard / alerting
