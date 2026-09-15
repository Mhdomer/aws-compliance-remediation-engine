import logging

import boto3
from botocore.exceptions import ClientError

from utils.cloudwatch_utils import publish_violation
from utils.notifier import send_alert

logger = logging.getLogger(__name__)

# Ports that must never be open to the public internet
RESTRICTED_PORTS = {22, 3389}
OPEN_CIDRS = {'0.0.0.0/0', '::/0'}

# EC2 uses "-1" to mean every protocol on every port. Such a rule carries no
# port range at all, and CloudTrail omits fromPort/toPort when it appears.
ALL_TRAFFIC = '-1'

_ec2_client = None


def _get_client():
    global _ec2_client
    if _ec2_client is None:
        _ec2_client = boto3.client('ec2')
    return _ec2_client


def _port_range(perm: dict) -> tuple[int | None, int | None]:
    """Return the permission's (from_port, to_port), or (None, None) for -1.

    Defaulting an all-traffic rule to 0-65535 would describe it as a TCP range,
    which is not the rule AWS stored — and a fabricated full range makes one
    rule look like it trips every restricted port independently.
    """
    if perm.get('ipProtocol', 'tcp') == ALL_TRAFFIC:
        return None, None
    return perm.get('fromPort', 0), perm.get('toPort', 65535)


def _covers_port(from_port: int | None, to_port: int | None, port: int) -> bool:
    if from_port is None:
        return True  # all-traffic reaches every port
    return from_port <= port <= to_port


def is_public_ingress(ip_permissions: list) -> list[dict]:
    """Return a list of violations found in the given IP permission items.

    One entry per restricted port exposed, so alerting can still name every
    port. Several entries may describe the same underlying ingress rule — pass
    them through group_by_rule() before remediating.
    """
    violations = []
    for perm in ip_permissions:
        protocol = perm.get('ipProtocol', 'tcp')
        from_port, to_port = _port_range(perm)

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
            # Sorted for a stable report order; set iteration order would
            # otherwise decide which port gets named first.
            for port in sorted(RESTRICTED_PORTS):
                if _covers_port(from_port, to_port, port):
                    violations.append({
                        'port': port,
                        'cidr': cidr,
                        'from_port': from_port,
                        'to_port': to_port,
                        'protocol': protocol,
                    })
    return violations


def group_by_rule(violations: list[dict]) -> list[dict]:
    """Collapse violations that revoke to the same ingress rule.

    A rule spanning 0-65535 (or -1) trips both 22 and 3389, but those are one
    rule, and _revoke_rule() builds its request from the range rather than the
    matched port. Revoking per violation therefore sends AWS the same request
    twice; the second gets InvalidPermission.NotFound for a rule that was just
    removed, and the engine reports a remediation failure for work it did.
    """
    grouped: dict[tuple, dict] = {}
    for violation in violations:
        key = (
            violation['cidr'],
            violation['from_port'],
            violation['to_port'],
            violation['protocol'],
        )
        rule = grouped.get(key)
        if rule is None:
            rule = {
                'ports': [],
                'cidr': violation['cidr'],
                'from_port': violation['from_port'],
                'to_port': violation['to_port'],
                'protocol': violation['protocol'],
            }
            grouped[key] = rule
        rule['ports'].append(violation['port'])
    return list(grouped.values())


def _revoke_rule(sg_id: str, rule: dict) -> None:
    ip_perm = {'IpProtocol': rule['protocol']}

    # Omit the port range for all-traffic rules so the request matches the rule
    # AWS actually holds.
    if rule['from_port'] is not None:
        ip_perm['FromPort'] = rule['from_port']
        ip_perm['ToPort'] = rule['to_port']

    if ':' in rule['cidr']:
        ip_perm['Ipv6Ranges'] = [{'CidrIpv6': rule['cidr']}]
    else:
        ip_perm['IpRanges'] = [{'CidrIp': rule['cidr']}]

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
    for rule in group_by_rule(violations):
        ports = rule['ports']

        for port in ports:
            logger.warning('Violation detected', extra={
                'violation': f'SG_OPEN_PORT_{port}',
                'sg_id': sg_id,
                'cidr': rule['cidr'],
                'actor': actor,
            })

        try:
            _revoke_rule(sg_id, rule)
            remediated = True
            label = 'port' if len(ports) == 1 else 'ports'
            action = (
                f"Revoked {rule['cidr']} access to {label} "
                f"{', '.join(str(p) for p in ports)}"
            )
            logger.info('Remediation applied', extra={'sg_id': sg_id, 'action': action})
        except ClientError as exc:
            remediated = False
            action = f'Revocation failed: {exc}'
            logger.error('Remediation failed', extra={'sg_id': sg_id, 'error': str(exc)})

        # One metric and one alert per exposed port, each carrying the outcome
        # of the single revoke that covered them all.
        for port in ports:
            violation_type = f'SG_OPEN_PORT_{port}'
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
