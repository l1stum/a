from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.request import urlopen

source_urls = [
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Russia/inside-raw.lst",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/YouTube/YouTube.list",
    "https://raw.githubusercontent.com/HybridNetworks/whatsapp-cidr/main/WhatsApp/whatsapp_cidr_ipv4.txt",
    "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/ru-blocked.txt",
    "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/ru-blocked-community.txt",
    "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/re-filter.txt",
    "https://raw.githubusercontent.com/misha-tgshv/shadowrocket-configuration-file/main/rules/domains_community.list",
]

BASE_DIR = Path(__file__).resolve().parents[1]
output_file = BASE_DIR / "a.list"

manual_rules = [
    "DOMAIN-SUFFIX,thinkingmachines.ai",
    "DOMAIN-SUFFIX,github.com",
    "DOMAIN-SUFFIX,githubusercontent.com",
]

seen = set()


def fetch_text(url: str) -> str:
    with urlopen(url, timeout=30) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset)


def is_ip_address(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def is_ip_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def is_public_ip(ip):
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_link_local
    )


def is_public_network(net):
    return not (
        net.is_private
        or net.is_loopback
        or net.is_reserved
        or net.is_multicast
        or net.is_link_local
    )


def normalize_known_rule(parts: list[str]) -> str | None:
    rule_type = parts[0]

    if rule_type in {"IP-CIDR", "IP-CIDR6"}:
        if len(parts) < 2:
            return None

        net_obj = is_ip_network(parts[1])
        if not net_obj or not is_public_network(net_obj):
            return None

        if "no-resolve" in parts[2:]:
            return f"{parts[0]},{parts[1]},no-resolve"

        return f"{parts[0]},{parts[1]}"

    if len(parts) >= 2:
        value = parts[1]
        if value == "RULE-SET" or "://" in value:
            return None
        return f"{parts[0]},{value}"

    return None


def normalize_raw_value(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None

    if value.startswith("http://"):
        value = value[len("http://"):].split("/", 1)[0].strip()
    elif value.startswith("https://"):
        value = value[len("https://"):].split("/", 1)[0].strip()

    if not value:
        return None

    ip_obj = is_ip_address(value)
    if ip_obj:
        if not is_public_ip(ip_obj):
            return None
        if ip_obj.version == 4:
            return f"IP-CIDR,{value}/32,no-resolve"
        return f"IP-CIDR6,{value}/128,no-resolve"

    net_obj = is_ip_network(value)
    if net_obj:
        if not is_public_network(net_obj):
            return None
        if net_obj.version == 4:
            return f"IP-CIDR,{value},no-resolve"
        return f"IP-CIDR6,{value},no-resolve"

    return f"DOMAIN-SUFFIX,{value}"


def normalize_line(line: str) -> str | None:
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    parts = [p.strip() for p in line.split(",")]
    rule_type = parts[0] if parts else ""

    if rule_type == "RULE-SET":
        return None

    known_types = {
        "DOMAIN-SUFFIX",
        "DOMAIN",
        "DOMAIN-KEYWORD",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP",
        "USER-AGENT",
    }

    if rule_type in known_types:
        return normalize_known_rule(parts)

    return normalize_raw_value(line)


def get_rule_value(rule: str) -> str:
    parts = [p.strip() for p in rule.split(",")]
    return parts[1] if len(parts) >= 2 else ""


def has_youtube_domain_coverage(rule_set: set[str]) -> bool:
    required = {
        "DOMAIN-SUFFIX,youtube.com",
        "DOMAIN-SUFFIX,youtu.be",
        "DOMAIN-SUFFIX,googlevideo.com",
        "DOMAIN-SUFFIX,ytimg.com",
    }
    return any(rule in rule_set for rule in required)


def is_redundant_youtube_keyword_rule(rule: str, rule_set: set[str]) -> bool:
    if not rule.startswith("DOMAIN-KEYWORD,"):
        return False

    value = get_rule_value(rule).lower()
    if value != "youtube":
        return False

    return has_youtube_domain_coverage(rule_set)


def is_redundant_youtube_user_agent_rule(rule: str, rule_set: set[str]) -> bool:
    if not rule.startswith("USER-AGENT,"):
        return False

    ua = get_rule_value(rule).lower()
    if not ua:
        return False

    youtube_markers = (
        "youtube",
        "youtubemusic",
        "com.google.ios.youtube",
        "com.google.ios.youtubemusic",
    )

    if not any(marker in ua for marker in youtube_markers):
        return False

    return has_youtube_domain_coverage(rule_set)


def cleanup_redundant_rules(rules: list[str]) -> list[str]:
    rule_set = set(rules)
    cleaned = []

    for rule in rules:
        if is_redundant_youtube_keyword_rule(rule, rule_set):
            continue
        if is_redundant_youtube_user_agent_rule(rule, rule_set):
            continue
        cleaned.append(rule)

    return cleaned


def sort_key(rule: str):
    if rule.startswith("DOMAIN-SUFFIX,"):
        return (0, rule)
    if rule.startswith("DOMAIN,"):
        return (1, rule)
    if rule.startswith("DOMAIN-KEYWORD,"):
        return (2, rule)
    if rule.startswith("USER-AGENT,"):
        return (3, rule)
    if rule.startswith("IP-CIDR,"):
        return (4, rule)
    if rule.startswith("IP-CIDR6,"):
        return (5, rule)
    if rule.startswith("GEOIP,"):
        return (6, rule)
    return (7, rule)


def add_rule(rule: str, target: list[str]) -> bool:
    if rule and rule not in seen:
        seen.add(rule)
        target.append(rule)
        return True
    return False


def add_rules_from_text(text: str, target: list[str], only_proxy_policy: bool = False) -> int:
    added = 0

    for raw_line in text.splitlines():
        if only_proxy_policy:
            parts = [p.strip() for p in raw_line.strip().split(",")]
            if len(parts) < 3 or parts[0] == "RULE-SET" or parts[2] != "PROXY":
                continue

        rule = normalize_line(raw_line)
        if add_rule(rule, target):
            added += 1

    return added


rules = []

if output_file.exists():
    existing_count = add_rules_from_text(output_file.read_text(encoding="utf-8"), rules)
    print(f"Preserved {existing_count} existing rules from {output_file}")

manual_count = 0
for raw_rule in manual_rules:
    rule = normalize_line(raw_rule)
    if add_rule(rule, rules):
        manual_count += 1
print(f"Loaded {manual_count} manual rules")

for url in source_urls:
    print(f"Fetching: {url}")
    text = fetch_text(url)
    source_count = add_rules_from_text(text, rules)
    print(f"Loaded {source_count} rules from {url}")

rules.sort(key=sort_key)

with open(output_file, "w", encoding="utf-8") as f:
    for rule in rules:
        f.write(rule + "\n")

print(f"Done. Wrote {len(rules)} rules to {output_file}")
