"""The MCP tools must agree with the engine about what counts as exempt.

The whole argument for these tools is that they apply the engine's own rules
rather than restating them. A tool reporting "exempt" for a resource the engine
would remediate is worse than no tool at all.
"""

from unittest.mock import MagicMock, patch

import pytest

EXPIRED = {'ComplianceExempt': 'true', 'ComplianceExemptUntil': '2020-01-01'}
NO_EXPIRY = {'ComplianceExempt': 'true'}
VALID = {'ComplianceExempt': 'true', 'ComplianceExemptUntil': '2099-12-31'}


@pytest.fixture(autouse=True)
def region(monkeypatch):
    monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')


def _tag_list(tags):
    return [{'Key': k, 'Value': v} for k, v in tags.items()]


@pytest.fixture
def clients():
    from mcp_server.tools import resource_state
    ec2, s3 = MagicMock(), MagicMock()
    with patch.object(resource_state, '_client', side_effect=lambda svc: {'ec2': ec2, 's3': s3}[svc]):
        yield ec2, s3


class TestResourceStateAgreesWithTheEngine:
    @pytest.mark.parametrize('tags,expected', [
        (VALID, True),
        (EXPIRED, False),
        (NO_EXPIRY, False),
    ])
    def test_instance_exemption_respects_expiry(self, clients, tags, expected):
        ec2, _ = clients
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'running'}, 'Tags': _tag_list(tags),
            'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
        }]}]}
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': True}]}

        from mcp_server.tools.resource_state import get_resource_state
        assert get_resource_state('i-abc')['exempt'] is expected

    def test_the_reason_is_reported_not_just_the_boolean(self, clients):
        ec2, _ = clients
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'running'}, 'Tags': _tag_list(EXPIRED),
            'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
        }]}]}
        ec2.describe_volumes.return_value = {'Volumes': [{'Encrypted': True}]}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('i-abc')

        # "not exempt" and "exempt but it lapsed last year" need different
        # follow-up, so the model needs to be able to tell them apart.
        assert result['exemption_status'] == 'expired'

    def test_bucket_exemption_respects_expiry(self, clients):
        _, s3 = clients
        s3.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {
            'BlockPublicAcls': True, 'IgnorePublicAcls': True,
            'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
        }}
        s3.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {
            'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms'}}]
        }}
        s3.get_bucket_tagging.return_value = {'TagSet': _tag_list(EXPIRED)}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('my-bucket')

        assert result['exempt'] is False
        assert result['exemption_status'] == 'expired'


@pytest.fixture
def tagging():
    from mcp_server.tools import exemptions
    client = MagicMock()
    with patch.object(exemptions, '_client', return_value=client):
        yield client


class TestListExemptionsSeparatesActiveFromLapsed:
    def test_expired_exemptions_are_not_counted_as_active(self, tagging):
        tagging.get_resources.return_value = {'ResourceTagMappingList': [
            {'ResourceARN': 'arn:aws:s3:::still-exempt', 'Tags': _tag_list(VALID)},
            {'ResourceARN': 'arn:aws:s3:::lapsed', 'Tags': _tag_list(EXPIRED)},
            {'ResourceARN': 'arn:aws:s3:::no-date', 'Tags': _tag_list(NO_EXPIRY)},
        ]}

        from mcp_server.tools.exemptions import list_exemptions
        result = list_exemptions()

        # Reporting all three as exempt would overstate the bypass and hide the
        # two that are already being checked again.
        assert result['active_count'] == 1
        assert result['rejected_count'] == 2

    def test_each_resource_carries_its_status(self, tagging):
        tagging.get_resources.return_value = {'ResourceTagMappingList': [
            {'ResourceARN': 'arn:aws:s3:::lapsed', 'Tags': _tag_list(EXPIRED)},
        ]}

        from mcp_server.tools.exemptions import list_exemptions
        entry = list_exemptions()['resources'][0]

        assert entry['exempt'] is False
        assert entry['status'] == 'expired'
