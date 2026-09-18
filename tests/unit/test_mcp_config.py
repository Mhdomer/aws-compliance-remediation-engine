import pytest


class TestLoadConfig:
    def test_region_must_be_set_explicitly(self, monkeypatch):
        monkeypatch.delenv('COMPLIANCE_REGION', raising=False)
        from mcp_server.config import ConfigError, load_config

        # boto3 would silently fall back to the CLI default (ap-southeast-1 on
        # this machine) while the engine deploys to us-east-1. Every query would
        # come back empty, and it would read as "no violations" rather than
        # "wrong region".
        with pytest.raises(ConfigError, match='COMPLIANCE_REGION'):
            load_config()

    def test_region_is_read_from_the_environment(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        from mcp_server.config import load_config
        assert load_config().region == 'us-east-1'

    def test_blank_region_is_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', '   ')
        from mcp_server.config import ConfigError, load_config
        with pytest.raises(ConfigError):
            load_config()

    def test_log_group_defaults_to_the_engine_function(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        monkeypatch.delenv('COMPLIANCE_LOG_GROUP', raising=False)
        from mcp_server.config import load_config
        assert load_config().log_group == '/aws/lambda/compliance-engine-prod'

    def test_log_group_can_be_overridden(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        monkeypatch.setenv('COMPLIANCE_LOG_GROUP', '/aws/lambda/other')
        from mcp_server.config import load_config
        assert load_config().log_group == '/aws/lambda/other'

    def test_namespace_matches_what_the_engine_publishes(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        from mcp_server.config import load_config
        from utils.cloudwatch_utils import NAMESPACE

        # Read the engine's own constant so the two cannot drift apart.
        assert load_config().metric_namespace == NAMESPACE
