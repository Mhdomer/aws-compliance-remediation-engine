import json
import logging


def _record(**extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name='rules.s3_rules', level=logging.WARNING, pathname=__file__,
        lineno=1, msg='Violation detected', args=(), exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestStructuredFormatter:
    def test_output_is_json(self):
        from utils.logger import StructuredFormatter
        entry = json.loads(StructuredFormatter().format(_record()))

        assert entry['level'] == 'WARNING'
        assert entry['message'] == 'Violation detected'
        assert 'timestamp' in entry

    def test_extra_fields_are_promoted_to_top_level_keys(self):
        from utils.logger import StructuredFormatter
        entry = json.loads(StructuredFormatter().format(
            _record(violation='S3_PUBLIC_ACL', bucket='my-bucket',
                    actor='arn:aws:iam::1:user/dev')
        ))

        # Logs Insights queries these as fields, so they must not be buried
        # inside the message string.
        assert entry['violation'] == 'S3_PUBLIC_ACL'
        assert entry['bucket'] == 'my-bucket'
        assert entry['actor'] == 'arn:aws:iam::1:user/dev'

    def test_logrecord_internals_are_not_leaked(self):
        from utils.logger import StructuredFormatter
        entry = json.loads(StructuredFormatter().format(_record(bucket='b')))

        for noisy in ('args', 'msg', 'pathname', 'lineno', 'thread', 'processName'):
            assert noisy not in entry

    def test_lambda_context_is_read_from_the_environment(self, monkeypatch):
        from utils.logger import StructuredFormatter
        monkeypatch.setenv('AWS_LAMBDA_FUNCTION_NAME', 'compliance-engine-prod')
        entry = json.loads(StructuredFormatter().format(_record()))

        assert entry['function'] == 'compliance-engine-prod'

    def test_falls_back_to_local_outside_lambda(self, monkeypatch):
        from utils.logger import StructuredFormatter
        monkeypatch.delenv('AWS_LAMBDA_FUNCTION_NAME', raising=False)
        entry = json.loads(StructuredFormatter().format(_record()))

        assert entry['function'] == 'local'

    def test_exception_is_included(self):
        from utils.logger import StructuredFormatter
        try:
            raise ValueError('boom')
        except ValueError:
            import sys
            record = _record()
            record.exc_info = sys.exc_info()
            entry = json.loads(StructuredFormatter().format(record))

        assert 'ValueError: boom' in entry['exception']

    def test_unserialisable_values_do_not_break_the_log_line(self):
        from utils.logger import StructuredFormatter
        entry = json.loads(StructuredFormatter().format(_record(result=object())))

        # default=str keeps a bad extra from taking down the whole record.
        assert 'object object at' in entry['result']


class TestSetupLogger:
    def test_handler_is_not_added_twice(self):
        from utils.logger import setup_logger
        first = setup_logger('test.dedupe')
        second = setup_logger('test.dedupe')

        assert first is second
        assert len(first.handlers) == 1

    def test_level_comes_from_the_environment(self, monkeypatch):
        from utils.logger import setup_logger
        monkeypatch.setenv('LOG_LEVEL', 'DEBUG')
        assert setup_logger('test.level.debug').level == logging.DEBUG

    def test_does_not_propagate_to_root(self):
        from utils.logger import setup_logger
        # Lambda's own root handler would otherwise print every record twice.
        assert setup_logger('test.propagate').propagate is False
