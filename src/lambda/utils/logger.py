import json
import logging
import os


class StructuredFormatter(logging.Formatter):
    _SKIP_KEYS = frozenset({
        'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
        'funcName', 'levelname', 'levelno', 'lineno', 'module', 'msecs',
        'message', 'msg', 'name', 'pathname', 'process', 'processName',
        'relativeCreated', 'stack_info', 'thread', 'threadName', 'taskName',
    })

    def format(self, record):
        entry = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'message': record.getMessage(),
            'function': os.environ.get('AWS_LAMBDA_FUNCTION_NAME', 'local'),
            'request_id': os.environ.get('_X_AMZN_TRACE_ID', 'local'),
        }
        for key, value in record.__dict__.items():
            if key not in self._SKIP_KEYS:
                entry[key] = value
        if record.exc_info:
            entry['exception'] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
    logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))
    logger.propagate = False
    return logger
