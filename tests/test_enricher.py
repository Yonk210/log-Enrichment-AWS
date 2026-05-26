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
