"""Exact, human-confirmed job context affects volume warnings only.

No source whitelist, model learning, attack-engine exemption or inferred peer.
Missing/partial/mixed flow evidence fails closed.
"""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Literal
from ipaddress import ip_address
import re

MAX_FLOWS = 16


class ExpectedFlowRule(BaseModel):
    peer_ip: str
    peer_mac: str
    protocol: Literal['tcp', 'udp']
    service_port: int = Field(ge=1, le=65535)
    direction: Literal['outbound'] = 'outbound'
    timezone: Literal['UTC', 'Asia/Seoul'] = 'Asia/Seoul'
    weekdays: list[int] = Field(min_length=1, max_length=7)
    start_hour: int = Field(ge=0, le=23)
    end_hour: int = Field(ge=1, le=24)
    max_bytes_per_tick: int = Field(ge=1, le=1024**4)
    purpose: str = Field(min_length=3, max_length=200)

    @model_validator(mode='after')
    def increasing_hours(self):
        if self.start_hour >= self.end_hour:
            raise ValueError('Split an overnight schedule into two daily rules')
        return self

    @field_validator('peer_ip')
    @classmethod
    def valid_ip(cls, value):
        address = ip_address(value)
        if address.is_multicast or address.is_unspecified:
            raise ValueError('Unicast peer required')
        return str(address)

    @field_validator('peer_mac')
    @classmethod
    def valid_mac(cls, value):
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value):
            raise ValueError('Exact peer MAC required')
        if int(value[:2], 16) & 1:
            raise ValueError('Unicast peer MAC required')
        return value.lower()

    @field_validator('weekdays')
    @classmethod
    def valid_days(cls, value):
        if any(type(day) is not int or day < 0 or day > 6 for day in value) or len(set(value)) != len(value):
            raise ValueError('Unique weekdays 0..6 required')
        return value


def expected_job(alert, device, *, shared_ip=False, now=None):
    from netwatcher.inventory.context import asset_context
    from netwatcher.detection.models import Severity
    if alert.engine != 'traffic_anomaly' or alert.title_key != 'engines.traffic_anomaly.alerts.volume.title':
        return False
    now = now or datetime.now(timezone.utc)
    context = asset_context(device, shared_ip=shared_ip, now=now)
    if context['status'] != 'confirmed' or context.get('role') not in ('nas', 'backup', 'database'):
        return False
    flows = alert.metadata.get('flows') or []
    if (not flows or len(flows) > MAX_FLOWS or alert.metadata.get('flows_incomplete')
            or alert.source_ip != str(device.get('ip_address'))):
        return False
    profile = device.get('context_profile') or {}
    rules = profile.get('expected_flows') or []
    if not rules or len(rules) > MAX_FLOWS:
        return False
    try:
        rules = [ExpectedFlowRule.model_validate(rule) for rule in rules]
        confirmed = datetime.fromisoformat(profile['confirmed_at']).timestamp()
        expires = datetime.fromisoformat(profile['expires_at']).timestamp()
        matched = set()
        usage = {}
        for flow in flows:
            first, last = flow['first_at'], flow['last_at']
            if (flow['source_mac'] != str(device['mac_address']).lower()
                    or first < confirmed or first > last or last > expires or last > now.timestamp() + 1
                    or not isinstance(flow['bytes'], int) or flow['bytes'] <= 0):
                return False
            choices = []
            for index, rule in enumerate(rules):
                start = datetime.fromtimestamp(first, ZoneInfo(rule.timezone))
                end = datetime.fromtimestamp(last, ZoneInfo(rule.timezone))
                if (start.date() == end.date() and start.weekday() in rule.weekdays
                        and rule.start_hour <= start.hour < rule.end_hour
                        and rule.start_hour <= end.hour < rule.end_hour
                        and flow['peer_ip'] == rule.peer_ip and flow['peer_mac'] == rule.peer_mac
                        and flow['protocol'] == rule.protocol and flow['service_port'] == rule.service_port):
                    choices.append(index)
            if len(choices) != 1:
                return False  # overlapping rules cannot multiply a volume allowance
            index = choices[0]
            usage[index] = usage.get(index, 0) + flow['bytes']
            if usage[index] > rules[index].max_bytes_per_tick:
                return False
            matched.add(index)
        if sum(flow['bytes'] for flow in flows) != alert.metadata.get('bytes'):
            return False
    except (KeyError, TypeError, ValueError, OverflowError):
        return False
    alert.metadata['business_context'] = {
        'state': 'expected_job', 'scope': 'outbound_volume_only',
        'context_version': context['version'], 'role': context['role'],
        'confirmed_by': context['confirmed_by'], 'expires_at': context['expires_at'],
        'rule_indexes': sorted(matched), 'original_severity': alert.severity.value,
        'model_learning_changed': False,
    }
    alert.expected_job_confirmed = True
    alert.severity = Severity.INFO
    return True
