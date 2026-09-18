"""Read the compliance engine's own definition of what it enforces.

Imports the Lambda source rather than copying its constants, so the two cannot
drift apart. The sys.path insert is the same one tests/conftest.py uses: the
Lambda is a flat package rooted at src/lambda, not an installed module, because
that directory is what archive_file zips and uploads.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LAMBDA_SRC = REPO_ROOT / 'src' / 'lambda'
EVENTBRIDGE_TF = REPO_ROOT / 'infrastructure' / 'eventbridge.tf'

if str(LAMBDA_SRC) not in sys.path:
    sys.path.insert(0, str(LAMBDA_SRC))


def eventbridge_pairs() -> set[tuple[str, str]]:
    """Return the (source, eventName) pairs terraform routes to the Lambda.

    Parsed from the terraform rather than the Python registry because the
    terraform is what decides which events are delivered at all. A registry
    entry with no matching rule never fires.
    """
    text = EVENTBRIDGE_TF.read_text(encoding='utf-8')

    pairs = set()
    for block in text.split('resource "aws_cloudwatch_event_rule"')[1:]:
        source = re.search(r'source\s*=\s*\["([^"]+)"\]', block)
        event = re.search(r'eventName\s*=\s*\["([^"]+)"\]', block)
        if source and event:
            pairs.add((source.group(1), event.group(1)))
    return pairs
