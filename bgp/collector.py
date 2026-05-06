import datetime
import ipaddress
from .parser import parse_cisco_bgp_summary, parse_juniper_bgp_summary, parse_bgp_routes, parse_peer_routes, parse_bgp_neighbor_detail

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


DEMO_PEER_DETAILS = {
    "10.0.0.2": {
        "state": "Established", "uptime": "2d03h", "remote_router_id": "10.0.0.2",
        "hold_time": 90, "keepalive": 30,
        "conn_established": 3, "conn_dropped": 2,
        "last_reset_time": "2d03h", "last_reset_reason": "BGP Notification received",
        "updates_sent": 12, "updates_rcvd": 48320,
        "keepalives_sent": 14880, "keepalives_rcvd": 14900,
        "local_host": "10.0.0.1", "local_port": 179,
        "foreign_host": "10.0.0.2", "foreign_port": 45231,
        "capabilities": ["4-byte AS", "Route Refresh", "IPv4 Unicast", "Graceful Restart"],
        "accepted_prefixes": 125840,
    },
    "10.0.0.3": {
        "state": "Established", "uptime": "5d12h", "remote_router_id": "10.0.0.3",
        "hold_time": 90, "keepalive": 30,
        "conn_established": 1, "conn_dropped": 0,
        "last_reset_time": "5d12h", "last_reset_reason": "—",
        "updates_sent": 8, "updates_rcvd": 850623,
        "keepalives_sent": 38880, "keepalives_rcvd": 38900,
        "local_host": "10.0.0.1", "local_port": 179,
        "foreign_host": "10.0.0.3", "foreign_port": 51422,
        "capabilities": ["4-byte AS", "Route Refresh", "IPv4 Unicast", "IPv6 Unicast", "Add-Path", "Enhanced RR"],
        "accepted_prefixes": 850623,
    },
    "192.168.1.4": {
        "state": "Idle", "uptime": "—", "remote_router_id": "—",
        "hold_time": None, "keepalive": None,
        "conn_established": 5, "conn_dropped": 5,
        "last_reset_time": "00:05:30", "last_reset_reason": "Hold Timer Expired",
        "updates_sent": 0, "updates_rcvd": 0,
        "keepalives_sent": 0, "keepalives_rcvd": 0,
        "local_host": "—", "local_port": None,
        "foreign_host": "—", "foreign_port": None,
        "capabilities": [],
        "accepted_prefixes": None,
    },
}


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
    try:
        ipaddress.IPv6Address(addr)
        return True
    except ValueError:
        return False


def _ip_equal(a: str, b: str) -> bool:
    """IPv6 アドレスの正規化比較（短縮形式の違いを吸収）。"""
    try:
        return ipaddress.ip_address(a.split('%')[0]) == ipaddress.ip_address(b.split('%')[0])
    except ValueError:
        return a == b


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
            # FRR / VyOS
            afi = "ipv6 unicast" if ipv6 else "ipv4 unicast"

            if route_type == "advertised":
                # VyOS/FRR バージョンによって有効なコマンドが異なるため順に試行
                # IPv4/IPv6 を混在させないよう AFI ごとに候補を分ける
                if ipv6:
                    adv_cmds = [
                        f"show bgp ipv6 unicast neighbors {neighbor} advertised-routes",
                        f"show bgp ipv6 neighbors {neighbor} advertised-routes",
                    ]
                else:
                    adv_cmds = [
                        f"show bgp ipv4 unicast neighbors {neighbor} advertised-routes",
                        f"show bgp neighbors {neighbor} advertised-routes",
                        f"show ip bgp neighbors {neighbor} advertised-routes",
                    ]
                routes = []
                for cmd in adv_cmds:
                    output = conn.send_command(cmd, read_timeout=60)
                    routes = parse_peer_routes(output)
                    if routes:
                        break
            else:
                output = conn.send_command(
                    f"show bgp {afi} neighbors {neighbor} routes", read_timeout=60)
                routes = parse_peer_routes(output)
                # soft-reconfiguration inbound 未設定時のフォールバック
                if len(routes) == 0:
                    full_output = conn.send_command(f"show bgp {afi}", read_timeout=60)
                    all_routes = parse_bgp_routes(full_output)
                    # 正規化比較（IPv6 短縮形式の違いを吸収）
                    routes = [r for r in all_routes if _ip_equal(r.get("next_hop", ""), neighbor)]
                    # IPv6 eBGP では next_hop がリンクローカル (fe80::) になる場合がある。
                    # 一致しない場合はローカル起源 (:: / 0.0.0.0) を除いた全ルートを返す。
                    if not routes and ipv6:
                        routes = [r for r in all_routes
                                  if r.get("next_hop", "") not in ("", "::", "0.0.0.0")]

            return routes

    return parse_peer_routes(output)


def fetch_peer_detail(config: dict, neighbor: str) -> dict:
    if config.get("device_type") == "demo":
        import time; time.sleep(0.2)
        default = {
            "state": "—", "uptime": "—", "remote_router_id": "—",
            "hold_time": None, "keepalive": None,
            "conn_established": 0, "conn_dropped": 0,
            "last_reset_time": "—", "last_reset_reason": "—",
            "updates_sent": 0, "updates_rcvd": 0,
            "keepalives_sent": 0, "keepalives_rcvd": 0,
            "local_host": "—", "local_port": None,
            "foreign_host": "—", "foreign_port": None,
            "capabilities": [], "accepted_prefixes": None,
        }
        return DEMO_PEER_DETAILS.get(neighbor, default)

    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise RuntimeError("netmiko がインストールされていません。")

    device = _build_device_params(config, timeout=20)
    dt = config["device_type"]

    with ConnectHandler(**device) as conn:
        if dt == "juniper_junos":
            output = conn.send_command(f"show bgp neighbor {neighbor}", read_timeout=30)
        elif dt in ("cisco_ios", "cisco_xr"):
            output = conn.send_command(f"show bgp neighbors {neighbor}", read_timeout=30)
            if "Invalid input" in output or "% Unknown" in output:
                output = conn.send_command(f"show ip bgp neighbors {neighbor}", read_timeout=30)
        else:
            output = conn.send_command(f"show bgp neighbors {neighbor}", read_timeout=30)

    return parse_bgp_neighbor_detail(output)
