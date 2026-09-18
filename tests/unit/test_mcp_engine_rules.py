class TestDescribeEngineRules:
    def test_reports_all_four_checks(self):
        from mcp_server.tools.engine_rules import describe_engine_rules
        result = describe_engine_rules()

        events = {c['event_name'] for c in result['checks']}
        assert events == {
            'PutBucketAcl', 'PutBucketEncryption',
            'RunInstances', 'AuthorizeSecurityGroupIngress',
        }

    def test_checks_match_what_terraform_actually_routes(self):
        from mcp_server.engine_source import eventbridge_pairs
        from mcp_server.tools.engine_rules import describe_engine_rules

        described = {(c['source'], c['event_name'])
                     for c in describe_engine_rules()['checks']}
        # Adding an EventBridge rule without describing it here would leave the
        # model unable to explain a check the engine actually enforces.
        assert described == eventbridge_pairs()

    def test_every_check_explains_itself(self):
        from mcp_server.tools.engine_rules import describe_engine_rules
        for check in describe_engine_rules()['checks']:
            assert check['detects'], f"{check['event_name']} has no description"
            assert check['remediates'], f"{check['event_name']} has no remediation"
            assert check['violation_type']

    def test_reads_the_engines_real_constants(self):
        from rules import ec2_rules, s3_rules, sg_rules
        from mcp_server.tools.engine_rules import describe_engine_rules
        result = describe_engine_rules()

        # Compared against the engine's own modules, so a change there shows up
        # here rather than the tool reporting a stale copy.
        assert result['restricted_ports'] == sorted(sg_rules.RESTRICTED_PORTS)
        assert result['required_sse_algorithm'] == s3_rules.REQUIRED_SSE_ALGORITHM
        assert result['exemption_tag'] == (
            f'{ec2_rules.EXEMPT_TAG_KEY}={ec2_rules.EXEMPT_TAG_VALUE}'
        )

    def test_mentions_the_cloudtrail_prerequisite(self):
        from mcp_server.tools.engine_rules import describe_engine_rules
        # Without a logging trail the engine receives nothing, so a model
        # explaining "no violations" needs to know that is a possible cause.
        assert 'CloudTrail' in describe_engine_rules()['note']

    def test_makes_no_aws_call(self):
        # The conftest guard fails any test that builds a real boto3 client,
        # so reaching this assertion at all proves the tool stayed offline.
        from mcp_server.tools.engine_rules import describe_engine_rules
        assert describe_engine_rules()['checks']
