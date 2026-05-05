import re
from typing import List, Dict, Any

def parse_cisco_bgp_summary(output: str) -> Dict[str, Any]:
    result = {"local_as": None, "router_id": None, "peers": [], "total_prefixes": 0}

    id_match = re.search(r'BGP router identifier\s+(\S+),\s+local AS number\s+(\d+)', output)
    if id_match:
        result["router_id"] = id_match.group(1)
        result["local_as"] = int(id_match.group(2))

    peer_pattern = re.compile(
        r'^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,}(?::[0-9a-fA-F]*)*)\s+'
        r'\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)',
        re.MULTILINE
    )

    for m in peer_pattern.finditer(output):
        neighbor   = m.group(1)
        remote_as  = int(m.group(2))
        msg_rcvd   = int(m.group(3))
        msg_sent   = int(m.group(4))
        updown     = m.group(5)
        state_raw  = m.group(6).strip()

        if state_raw.isdigit():
            state        = "Established"
            prefix_count = int(state_raw)
            result["total_prefixes"] += prefix_count
        else:
            state        = state_raw
            prefix_count = 0

        result["peers"].append({
            "neighbor":     neighbor,
            "remote_as":    remote_as,
            "state":        state,
            "prefix_count": prefix_count,
            "updown":       updown,
            "msg_rcvd":     msg_rcvd,
            "msg_sent":     msg_sent,
        })

    return result


def parse_juniper_bgp_summary(output: str) -> Dict[str, Any]:
    result = {"local_as": None, "router_id": None, "peers": [], "total_prefixes": 0}

    peer_pattern = re.compile(
        r'^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+'
        r'(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)',
        re.MULTILINE
    )

    for m in peer_pattern.finditer(output):
        state_str = m.group(6)
        state     = "Established" if state_str.startswith("Establ") else state_str

        result["peers"].append({
            "neighbor":     m.group(1),
            "remote_as":    int(m.group(2)),
            "state":        state,
            "prefix_count": 0,
            "updown":       m.group(5),
            "msg_rcvd":     int(m.group(3)),
            "msg_sent":     int(m.group(4)),
        })

    return result


def parse_peer_routes(output: str) -> List[Dict]:
    """show bgp neighbors <ip> advertised-routes / routes の共通パーサー"""
    routes = []

    # Metric・LocPrf は空欄になる場合があるため \d* (0文字以上) で対応
    route_pattern = re.compile(
        r'^[ *>sidh=rRSmb]+'
        r'(\d{1,3}(?:\.\d{1,3}){3}/\d+|[0-9a-fA-F:]+/\d+)\s+'
        r'(\S+)\s+'
        r'(\d*)\s+'
        r'(\d*)\s+'
        r'(\d+)\s+'
        r'([\d\s]*?)'
        r'([ie?])\s*$',
        re.MULTILINE
    )

    for m in route_pattern.finditer(output):
        routes.append({
            "prefix":     m.group(1),
            "next_hop":   m.group(2),
            "metric":     m.group(3) or "0",
            "local_pref": m.group(4) or "0",
            "weight":     m.group(5),
            "as_path":    m.group(6).strip(),
            "origin":     m.group(7),
        })

    return routes


def parse_bgp_routes(output: str) -> List[Dict]:
    routes = []

    route_pattern = re.compile(
        r'^[ *>sidh=rRSmb]+'
        r'(\d{1,3}(?:\.\d{1,3}){3}/\d+|[0-9a-fA-F:]+/\d+)\s+'
        r'(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d\s]*?)([ie?])\s*$',
        re.MULTILINE
    )

    for m in route_pattern.finditer(output):
        routes.append({
            "prefix":     m.group(1),
            "next_hop":   m.group(2),
            "metric":     m.group(3),
            "local_pref": m.group(4),
            "weight":     m.group(5),
            "as_path":    m.group(6).strip(),
            "origin":     m.group(7),
        })

    return routes
