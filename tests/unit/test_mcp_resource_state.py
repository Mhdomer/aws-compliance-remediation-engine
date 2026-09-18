from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


def _error(code: str) -> ClientError:
    return ClientError({'Error': {'Code': code, 'Message': ''}}, 'Op')


@pytest.fixture(autouse=True)
def region(monkeypatch):
    monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')


@pytest.fixture
def clients():
    """Patch the per-service factory and hand back the two mock clients."""
    from mcp_server.tools import resource_state
    ec2, s3 = MagicMock(), MagicMock()

    def pick(service):
        return {'ec2': ec2, 's3': s3}[service]

    with patch.object(resource_state, '_client', side_effect=pick):
        yield ec2, s3


class TestInstanceState:
    def test_unencrypted_volume_is_reported(self, clients):
        ec2, _ = clients
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'running'}, 'Tags': [],
            'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
        }]}]}
        ec2.describe_volumes.return_value = {'Volumes': [
            {'VolumeId': 'vol-a', 'Encrypted': False}
        ]}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('i-0abc123')

        assert result['resource_type'] == 'ec2_instance'
        assert result['compliant'] is False
        assert result['volumes'] == [{'volume_id': 'vol-a', 'encrypted': False}]

    def test_encrypted_volume_is_compliant(self, clients):
        ec2, _ = clients
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'running'}, 'Tags': [],
            'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
        }]}]}
        ec2.describe_volumes.return_value = {'Volumes': [
            {'VolumeId': 'vol-a', 'Encrypted': True}
        ]}

        from mcp_server.tools.resource_state import get_resource_state
        assert get_resource_state('i-0abc123')['compliant'] is True

    def test_pending_instance_is_undetermined_not_compliant(self, clients):
        ec2, _ = clients
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'pending'}, 'Tags': [], 'BlockDeviceMappings': [],
        }]}]}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('i-0abc123')

        # Same rule the engine itself applies: an empty mapping list on a
        # pending instance means "cannot tell", never "clean".
        assert result['compliant'] is None
        assert 'undetermined' in result['note'].lower()

    def test_exemption_tag_is_surfaced(self, clients):
        ec2, _ = clients
        ec2.describe_instances.return_value = {'Reservations': [{'Instances': [{
            'State': {'Name': 'running'},
            # An exemption now needs an expiry date to count.
            'Tags': [
                {'Key': 'ComplianceExempt', 'Value': 'true'},
                {'Key': 'ComplianceExemptUntil', 'Value': '2099-12-31'},
            ],
            'BlockDeviceMappings': [{'Ebs': {'VolumeId': 'vol-a'}}],
        }]}]}
        ec2.describe_volumes.return_value = {'Volumes': [
            {'VolumeId': 'vol-a', 'Encrypted': False}
        ]}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('i-0abc123')

        # The engine would skip this resource entirely, so the state alone is
        # misleading without it.
        assert result['exempt'] is True

    def test_missing_instance_is_reported(self, clients):
        ec2, _ = clients
        ec2.describe_instances.side_effect = _error('InvalidInstanceID.NotFound')

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('i-0abc123')

        assert result['found'] is False
        assert 'InvalidInstanceID.NotFound' in result['error']


class TestSecurityGroupState:
    def test_open_ssh_is_reported_non_compliant(self, clients):
        ec2, _ = clients
        ec2.describe_security_groups.return_value = {'SecurityGroups': [{
            'GroupId': 'sg-0abc123', 'GroupName': 'web',
            'IpPermissions': [{
                'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [],
            }],
        }]}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('sg-0abc123')

        assert result['resource_type'] == 'security_group'
        assert result['compliant'] is False
        assert 22 in result['open_restricted_ports']

    def test_all_traffic_rule_is_caught(self, clients):
        ec2, _ = clients
        ec2.describe_security_groups.return_value = {'SecurityGroups': [{
            'GroupId': 'sg-0abc123', 'GroupName': 'web',
            'IpPermissions': [{
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [],
            }],
        }]}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('sg-0abc123')

        # -1 carries no port range but reaches every port.
        assert sorted(result['open_restricted_ports']) == [22, 3389]

    def test_private_cidr_is_compliant(self, clients):
        ec2, _ = clients
        ec2.describe_security_groups.return_value = {'SecurityGroups': [{
            'GroupId': 'sg-0abc123', 'GroupName': 'web',
            'IpPermissions': [{
                'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                'IpRanges': [{'CidrIp': '10.0.0.0/8'}], 'Ipv6Ranges': [],
            }],
        }]}

        from mcp_server.tools.resource_state import get_resource_state
        assert get_resource_state('sg-0abc123')['compliant'] is True


class TestBucketState:
    def test_public_access_block_and_encryption_are_reported(self, clients):
        _, s3 = clients
        s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
            }
        }
        s3.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms'}}
            ]}
        }
        s3.get_bucket_tagging.return_value = {'TagSet': []}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('my-bucket')

        assert result['resource_type'] == 's3_bucket'
        assert result['public_access_blocked'] is True
        assert result['sse_algorithm'] == 'aws:kms'
        assert result['compliant'] is True

    def test_sse_s3_is_non_compliant_against_the_engines_policy(self, clients):
        _, s3 = clients
        s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
            }
        }
        s3.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}
            ]}
        }
        s3.get_bucket_tagging.return_value = {'TagSet': []}

        from mcp_server.tools.resource_state import get_resource_state
        assert get_resource_state('my-bucket')['compliant'] is False

    def test_absent_public_access_block_is_not_treated_as_blocked(self, clients):
        _, s3 = clients
        s3.get_public_access_block.side_effect = _error(
            'NoSuchPublicAccessBlockConfiguration'
        )
        s3.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms'}}
            ]}
        }
        s3.get_bucket_tagging.return_value = {'TagSet': []}

        from mcp_server.tools.resource_state import get_resource_state
        result = get_resource_state('my-bucket')

        assert result['public_access_blocked'] is False
        assert result['compliant'] is False

    def test_no_tags_is_not_exempt(self, clients):
        _, s3 = clients
        s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': True, 'IgnorePublicAcls': True,
                'BlockPublicPolicy': True, 'RestrictPublicBuckets': True,
            }
        }
        s3.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms'}}
            ]}
        }
        s3.get_bucket_tagging.side_effect = _error('NoSuchTagSet')

        from mcp_server.tools.resource_state import get_resource_state
        assert get_resource_state('my-bucket')['exempt'] is False
