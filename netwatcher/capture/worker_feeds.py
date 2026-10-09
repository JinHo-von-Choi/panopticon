"""워커에 전달하는 읽기 전용 위협 지표. 자격증명·다운로드 상태는 제외한다."""

import ipaddress
import json

from netwatcher.threatintel.feed_manager import FeedManager

MAX_FEED_BYTES = 32 * 1024 * 1024
MAX_INDICATORS = 1_000_000


def feed_payload(manager) -> str:
    if manager is None:
        return "null"
    value = {"ips": {ip: source for ip, source in manager._ip_to_feed.items() if ip not in manager._custom_ips},
             "domains": dict(manager._domain_to_feed),
             "custom_ips": sorted(manager._custom_ips), "custom_domains": sorted(manager._custom_domains),
             "ja3": sorted(manager._blocked_ja3), "ja3_names": dict(manager._ja3_to_malware),
             "ja4": sorted(getattr(manager, "_blocked_ja4", ())),
             "ja4_names": dict(getattr(manager, "_ja4_to_malware", {}))}
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    WorkerFeeds.from_payload(payload)
    return payload


class WorkerFeeds:
    """부모와 같은 IP·CIDR·도메인 매칭을 제공하며 외부 통신을 하지 않는다."""

    match_ip = FeedManager.match_ip
    match_domain = FeedManager.match_domain
    _domain_name = staticmethod(FeedManager._domain_name)
    get_blocked_ips = FeedManager.get_blocked_ips
    get_blocked_domains = FeedManager.get_blocked_domains
    get_feed_for_ip = FeedManager.get_feed_for_ip
    get_feed_for_domain = FeedManager.get_feed_for_domain

    @classmethod
    def from_payload(cls, payload: str):
        if not isinstance(payload, str) or len(payload.encode()) > MAX_FEED_BYTES:
            raise ValueError("Worker feed snapshot exceeds capacity")
        value = json.loads(payload)
        if value is None:
            return None
        maps = {"ips", "domains", "ja3_names", "ja4_names"}
        lists = {"custom_ips", "custom_domains", "ja3", "ja4"}
        if not isinstance(value, dict) or set(value) != maps | lists:
            raise ValueError("Invalid worker feed snapshot")
        for key in maps:
            if (not isinstance(value[key], dict)
                    or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value[key].items())):
                raise ValueError("Invalid worker feed mapping")
        for key in lists:
            if not isinstance(value[key], list) or any(not isinstance(item, str) for item in value[key]):
                raise ValueError("Invalid worker feed entries")
        if sum(len(entries) for entries in value.values()) > MAX_INDICATORS:
            raise ValueError("Worker feed indicator capacity exceeded")
        result = cls()
        result._ip_to_feed = {str(ipaddress.ip_address(ip)): source for ip, source in value["ips"].items()}
        result._domain_to_feed = {cls._domain_name(domain): source for domain, source in value["domains"].items()}
        result._custom_networks = {4: {}, 6: {}}
        for entry in value["custom_ips"]:
            if "/" in entry:
                network = ipaddress.ip_network(entry, strict=False)
                networks = result._custom_networks[network.version].setdefault(network.prefixlen, {})
                networks.setdefault(int(network.network_address), set()).add(str(network))
            else:
                result._ip_to_feed[str(ipaddress.ip_address(entry))] = "Custom"
        result._custom_domain_names = {cls._domain_name(domain): {domain} for domain in value["custom_domains"]}
        result._blocked_ips = set(result._ip_to_feed)
        result._blocked_domains = set(result._domain_to_feed) | set(result._custom_domain_names)
        result._blocked_ja3 = set(value["ja3"])
        result._ja3_to_malware = dict(value["ja3_names"])
        result._blocked_ja4 = set(value["ja4"])
        result._ja4_to_malware = dict(value["ja4_names"])
        return result
