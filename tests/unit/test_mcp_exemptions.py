from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError


@pytest.fixture(autouse=True)
def region(monkeypatch):
    monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')


@pytest.fixture
def tagging():
    from mcp_server.tools import exemptions
    client = MagicMock()
    client.get_resources.return_value = {'ResourceTagMappingList': []}
    with patch.object(exemptions, '_client', return_value=client):
        yield client


class TestListExemptions:
    def test_exempt_resources_are_listed(self, tagging):
        from mcp_server.tools.exemptions import list_exemptions
        tagging.get_resources.return_value = {'ResourceTagMappingList': [
            {'ResourceARN': 'arn:aws:s3:::my-bucket',
             'Tags': [{'Key': 'ComplianceExempt', 'Value': 'true'}]},
        ]}

        result = list_exemptions()

        assert result['count'] == 1
        assert result['resources'][0]['arn'] == 'arn:aws:s3:::my-bucket'

    def test_filters_on_the_engines_exemption_tag(self, tagging):
        from rules import ec2_rules
        from mcp_server.tools.exemptions import list_exemptions
        list_exemptions()

        _, kwargs = tagging.get_resources.call_args
        assert kwargs['TagFilters'] == [{
            'Key': ec2_rules.EXEMPT_TAG_KEY,
            'Values': [ec2_rules.EXEMPT_TAG_VALUE],
        }]

    def test_pagination_is_followed(self, tagging):
        from mcp_server.tools.exemptions import list_exemptions
        tagging.get_resources.side_effect = [
            {'ResourceTagMappingList': [
                {'ResourceARN': 'arn:aws:s3:::a', 'Tags': []}],
             'PaginationToken': 'more'},
            {'ResourceTagMappingList': [
                {'ResourceARN': 'arn:aws:s3:::b', 'Tags': []}],
             'PaginationToken': ''},
        ]

        result = list_exemptions()

        # Stopping at page one would under-report an active bypass.
        assert result['count'] == 2
        assert tagging.get_resources.call_count == 2

    def test_resource_type_is_derived_from_the_arn(self, tagging):
        from mcp_server.tools.exemptions import list_exemptions
        tagging.get_resources.return_value = {'ResourceTagMappingList': [
            {'ResourceARN': 'arn:aws:s3:::my-bucket', 'Tags': []},
            {'ResourceARN': 'arn:aws:ec2:us-east-1:1:instance/i-abc', 'Tags': []},
        ]}

        types = {r['service'] for r in list_exemptions()['resources']}
        assert types == {'s3', 'ec2'}

    def test_none_found_is_stated_plainly(self, tagging):
        from mcp_server.tools.exemptions import list_exemptions
        result = list_exemptions()

        assert result['count'] == 0
        assert result['resources'] == []

    def test_explains_what_an_exemption_means(self, tagging):
        from mcp_server.tools.exemptions import list_exemptions
        note = list_exemptions()['note'].lower()

        # The tag is an authorisation boundary granted by ordinary tagging
        # permissions. A model reporting on it needs to know that.
        assert 'tagging' in note or 'bypass' in note

    def test_missing_permission_is_reported_not_swallowed(self, tagging):
        from mcp_server.tools.exemptions import list_exemptions
        tagging.get_resources.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}},
            'GetResources',
        )

        result = list_exemptions()

        # "I could not look" must never render as "there are none".
        assert result['count'] is None
        assert 'AccessDenied' in result['error']
