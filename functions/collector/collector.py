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
