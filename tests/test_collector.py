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
