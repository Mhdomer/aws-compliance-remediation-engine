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
        monkeypatch.setenv('COMPLIANCE_LOG_GROUP', '/aws/lambda/engine')
        from mcp_server.config import load_config
        assert load_config().region == 'us-east-1'

    def test_blank_region_is_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', '   ')
        from mcp_server.config import ConfigError, load_config
        with pytest.raises(ConfigError):
            load_config()

    def test_log_group_must_be_set_explicitly(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        monkeypatch.delenv('COMPLIANCE_LOG_GROUP', raising=False)
        from mcp_server.config import ConfigError, load_config

        # This used to default to compliance-engine-prod while the only tfvars
        # in this repo deploys "test". Two of the six tools queried a log group
        # the project never creates, and the default was wrong for the repo's
        # own default deployment. Found on a live account, entry 17.
        with pytest.raises(ConfigError, match='COMPLIANCE_LOG_GROUP'):
            load_config()

    def test_blank_log_group_is_treated_as_unset(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        monkeypatch.setenv('COMPLIANCE_LOG_GROUP', '   ')
        from mcp_server.config import ConfigError, load_config
        with pytest.raises(ConfigError):
            load_config()

    def test_log_group_is_read_from_the_environment(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        monkeypatch.setenv('COMPLIANCE_LOG_GROUP', '/aws/lambda/other')
        from mcp_server.config import load_config
        assert load_config().log_group == '/aws/lambda/other'

    def test_the_error_names_where_to_find_the_value(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        monkeypatch.delenv('COMPLIANCE_LOG_GROUP', raising=False)
        from mcp_server.config import ConfigError, load_config

        # An error that says a variable is missing without saying what to put
        # in it just moves the guessing somewhere else.
        with pytest.raises(ConfigError) as exc:
            load_config()
        assert 'project_name' in str(exc.value)
        assert 'environment' in str(exc.value)

    def test_namespace_matches_what_the_engine_publishes(self, monkeypatch):
        monkeypatch.setenv('COMPLIANCE_REGION', 'us-east-1')
        monkeypatch.setenv('COMPLIANCE_LOG_GROUP', '/aws/lambda/engine')
        from mcp_server.config import load_config
        from utils.cloudwatch_utils import NAMESPACE

        # Read the engine's own constant so the two cannot drift apart.
        assert load_config().metric_namespace == NAMESPACE
