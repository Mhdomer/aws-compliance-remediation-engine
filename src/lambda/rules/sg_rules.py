import logging

import boto3
from botocore.exceptions import ClientError

from utils.cloudwatch_utils import publish_violation
from utils.notifier import send_alert

logger = logging.getLogger(__name__)

# Ports that must never be open to the public internet
RESTRICTED_PORTS = {22, 3389}
OPEN_CIDRS = {'0.0.0.0/0', '::/0'}

_ec2_client = None


def _get_client():
    global _ec2_client
    if _ec2_client is None:
        _ec2_client = boto3.client('ec2')
    return _ec2_client


def is_public_ingress(ip_permissions: list) -> list[dict]:
    """Return a list of violations found in the given IP permission items."""
    violations = []
    for perm in ip_permissions:
        from_port = perm.get('fromPort', 0)
        to_port = perm.get('toPort', 65535)
        protocol = perm.get('ipProtocol', 'tcp')

        # CloudTrail wraps EC2 repeated elements in {"items": [...]} rather than a
        # bare list (confirmed against a real AuthorizeSecurityGroupIngress event) —
        # ipRanges/ipv6Ranges need unwrapping the same way ipPermissions.items does.
        cidrs = (
            [r.get('cidrIp', '') for r in perm.get('ipRanges', {}).get('items', [])] +
            [r.get('cidrIpv6', '') for r in perm.get('ipv6Ranges', {}).get('items', [])]
        )

        for cidr in cidrs:
            if cidr not in OPEN_CIDRS:
                continue
            for port in RESTRICTED_PORTS:
                if from_port <= port <= to_port:
                    violations.append({
                        'port': port,
                        'cidr': cidr,
                        'from_port': from_port,
                        'to_port': to_port,
                        'protocol': protocol,
                    })
    return violations


def _revoke_rule(sg_id: str, violation: dict) -> None:
    ip_perm = {
        'IpProtocol': violation['protocol'],
        'FromPort': violation['from_port'],
        'ToPort': violation['to_port'],
    }
    if ':' in violation['cidr']:
        ip_perm['Ipv6Ranges'] = [{'CidrIpv6': violation['cidr']}]
    else:
        ip_perm['IpRanges'] = [{'CidrIp': violation['cidr']}]

    _get_client().revoke_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[ip_perm],
    )


def handle_authorize_sg_ingress(detail: dict) -> dict:
    actor = detail.get('userIdentity', {}).get('arn', 'unknown')
    sg_id = detail.get('requestParameters', {}).get('groupId', '')

    if not sg_id:
        logger.error('AuthorizeSecurityGroupIngress event missing groupId')
        return {'status': 'error', 'reason': 'missing_sg_id'}

    ip_permissions = (
        detail.get('requestParameters', {})
              .get('ipPermissions', {})
              .get('items', [])
    )

    violations = is_public_ingress(ip_permissions)
    if not violations:
        return {'status': 'compliant', 'sg': sg_id}

    results = []
    for violation in violations:
        violation_type = f"SG_OPEN_PORT_{violation['port']}"
        logger.warning('Violation detected', extra={
            'violation': violation_type,
            'sg_id': sg_id,
            'cidr': violation['cidr'],
            'actor': actor,
        })

        try:
            _revoke_rule(sg_id, violation)
            remediated = True
            action = f"Revoked {violation['cidr']} access to port {violation['port']}"
            logger.info('Remediation applied', extra={'sg_id': sg_id, 'action': action})
        except ClientError as exc:
            remediated = False
            action = f'Revocation failed: {exc}'
            logger.error('Remediation failed', extra={'sg_id': sg_id, 'error': str(exc)})

        publish_violation(violation_type, sg_id, remediated)
        send_alert(violation_type, sg_id, actor, action, remediated)

        results.append({
            'sg': sg_id,
            'violation': violation_type,
            'status': 'remediated' if remediated else 'remediation_failed',
            'action': action,
        })

    return {'status': 'processed', 'results': results}


_HANDLERS = {
    'AuthorizeSecurityGroupIngress': handle_authorize_sg_ingress,
}


def evaluate(event_name: str, detail: dict) -> dict:
    handler = _HANDLERS.get(event_name)
    if handler:
        return handler(detail)
    return {'status': 'no_rule', 'event': event_name}
