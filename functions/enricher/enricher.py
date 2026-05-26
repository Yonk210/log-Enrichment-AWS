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
