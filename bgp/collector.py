import datetime
from .parser import parse_cisco_bgp_summary, parse_juniper_bgp_summary, parse_bgp_routes, parse_peer_routes

# デモ用モックデータ
DEMO_SUMMARY = {
    "local_as": 65000,
    "router_id": "192.0.2.1",
    "peers": [
        {"neighbor": "10.0.0.2",    "remote_as": 65001, "state": "Established", "prefix_count": 125840, "updown": "2d03h",   "msg_rcvd": 15200, "msg_sent": 14900},
        {"neighbor": "10.0.0.3",    "remote_as": 65002, "state": "Established", "prefix_count": 850623, "updown": "5d12h",   "msg_rcvd": 45000, "msg_sent": 44500},
        {"neighbor": "192.168.1.4", "remote_as": 65003, "state": "Idle",        "prefix_count": 0,      "updown": "00:05:30","msg_rcvd": 0,     "msg_sent": 0},
        {"neighbor": "172.16.0.1",  "remote_as": 65004, "state": "Active",      "prefix_count": 0,      "updown": "never",   "msg_rcvd": 0,     "msg_sent": 0},
        {"neighbor": "10.1.0.1",    "remote_as": 65005, "state": "Established", "prefix_count": 42,     "updown": "01:23:45","msg_rcvd": 200,   "msg_sent": 195},
    ],
    "total_prefixes": 976505,
}

DEMO_ROUTES = [
    {"prefix": "8.8.8.0/24",    "next_hop": "10.0.0.2",    "metric": "0", "local_pref": "100", "weight": "0",     "as_path": "65001 15169",       "origin": "i"},
    {"prefix": "1.1.1.0/24",    "next_hop": "10.0.0.3",    "metric": "0", "local_pref": "100", "weight": "0",     "as_path": "65002 13335",       "origin": "i"},
    {"prefix": "0.0.0.0/0",     "next_hop": "10.0.0.2",    "metric": "0", "local_pref": "80",  "weight": "0",     "as_path": "65001",             "origin": "i"},
    {"prefix": "192.0.2.0/24",  "next_hop": "0.0.0.0",     "metric": "0", "local_pref": "100", "weight": "32768", "as_path": "",                  "origin": "i"},
    {"prefix": "203.0.113.0/24","next_hop": "10.1.0.1",    "metric": "5", "local_pref": "100", "weight": "0",     "as_path": "65005 64512",       "origin": "e"},
]


def _build_device_params(config: dict, timeout: int = 20) -> dict:
    key = config.get("ssh_key_path", "").strip()
    params = {
        "device_type":  config["device_type"],
        "host":         config["host"],
        "username":     config["username"],
        "port":         config.get("port", 22),
        "timeout":      timeout,
        "conn_timeout": 10,
    }
    if key:
        params["use_keys"]  = True
        params["key_file"]  = key
        params["password"]  = ""
    else:
        params["password"]  = config.get("password", "")
    return params


def fetch_bgp_summary(config: dict) -> dict:
    if config.get("device_type") == "demo":
        import time; time.sleep(0.3)
        return {**DEMO_SUMMARY, "last_updated": datetime.datetime.now().isoformat()}

    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise RuntimeError("netmiko がインストールされていません。pip install netmiko を実行してください。")

    device = _build_device_params(config, timeout=20)

    with ConnectHandler(**device) as conn:
        dt = config["device_type"]
        if dt == "juniper_junos":
            output = conn.send_command("show bgp summary", read_timeout=30)
            result = parse_juniper_bgp_summary(output)
        else:
            output = conn.send_command("show bgp summary", read_timeout=30)
            if "Invalid input" in output or "% Unknown" in output:
                output = conn.send_command("show ip bgp summary", read_timeout=30)
            result = parse_cisco_bgp_summary(output)

    return result


def fetch_bgp_routes(config: dict) -> list:
    if config.get("device_type") == "demo":
        return DEMO_ROUTES

    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise RuntimeError("netmiko がインストールされていません。")

    device = _build_device_params(config, timeout=30)

    with ConnectHandler(**device) as conn:
        if config["device_type"] == "juniper_junos":
            output = conn.send_command("show route protocol bgp", read_timeout=60)
        else:
            output = conn.send_command("show ip bgp", read_timeout=60)

    return parse_bgp_routes(output)


DEMO_PEER_ADVERTISED = [
    {"prefix": "192.0.2.0/24",   "next_hop": "0.0.0.0",  "metric": "0", "local_pref": "100", "weight": "32768", "as_path": "",        "origin": "i"},
    {"prefix": "203.0.113.0/24", "next_hop": "0.0.0.0",  "metric": "0", "local_pref": "100", "weight": "32768", "as_path": "",        "origin": "i"},
    {"prefix": "10.0.0.0/8",     "next_hop": "0.0.0.0",  "metric": "0", "local_pref": "100", "weight": "32768", "as_path": "",        "origin": "i"},
]

DEMO_PEER_RECEIVED = [
    {"prefix": "8.8.8.0/24",  "next_hop": "10.0.0.2", "metric": "0", "local_pref": "100", "weight": "0", "as_path": "65001 15169", "origin": "i"},
    {"prefix": "8.8.4.0/24",  "next_hop": "10.0.0.2", "metric": "0", "local_pref": "100", "weight": "0", "as_path": "65001 15169", "origin": "i"},
    {"prefix": "1.1.1.0/24",  "next_hop": "10.0.0.2", "metric": "0", "local_pref": "100", "weight": "0", "as_path": "65001 13335", "origin": "i"},
]


def _is_ipv6(addr: str) -> bool:
    import ipaddress
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ValueError:
        return False


def fetch_peer_routes(config: dict, neighbor: str, route_type: str) -> list:
    """route_type: 'advertised' or 'received'"""
    if config.get("device_type") == "demo":
        return DEMO_PEER_ADVERTISED if route_type == "advertised" else DEMO_PEER_RECEIVED

    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise RuntimeError("netmiko がインストールされていません。")

    device = _build_device_params(config, timeout=30)
    dt = config["device_type"]
    ipv6 = _is_ipv6(neighbor)

    with ConnectHandler(**device) as conn:
        if dt == "juniper_junos":
            cmd = (f"show route advertising-protocol bgp {neighbor}"
                   if route_type == "advertised"
                   else f"show route receive-protocol bgp {neighbor}")
            output = conn.send_command(cmd, read_timeout=60)

        elif dt in ("cisco_ios", "cisco_xr"):
            # Cisco IOS/XR: IPv4 は "show ip bgp", IPv6 は "show bgp ipv6 unicast"
            if ipv6:
                cmd = (f"show bgp ipv6 unicast neighbors {neighbor} advertised-routes"
                       if route_type == "advertised"
                       else f"show bgp ipv6 unicast neighbors {neighbor} routes")
            else:
                cmd = (f"show ip bgp neighbors {neighbor} advertised-routes"
                       if route_type == "advertised"
                       else f"show ip bgp neighbors {neighbor} routes")
            output = conn.send_command(cmd, read_timeout=60)
            # "show bgp" が通らない旧 IOS 向けフォールバック
            if "Invalid input" in output or "% Unknown" in output:
                cmd2 = (f"show bgp neighbors {neighbor} advertised-routes"
                        if route_type == "advertised"
                        else f"show bgp neighbors {neighbor} routes")
                output = conn.send_command(cmd2, read_timeout=60)

        else:
            # FRR / VyOS / Linux: "show bgp neighbors X" は IPv4・IPv6 どちらも対応
            cmd = (f"show bgp neighbors {neighbor} advertised-routes"
                   if route_type == "advertised"
                   else f"show bgp neighbors {neighbor} routes")
            output = conn.send_command(cmd, read_timeout=60)

    return parse_peer_routes(output)
