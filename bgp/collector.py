import datetime
from .parser import parse_cisco_bgp_summary, parse_juniper_bgp_summary, parse_bgp_routes

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


def fetch_bgp_summary(config: dict) -> dict:
    if config.get("device_type") == "demo":
        import time; time.sleep(0.3)
        return {**DEMO_SUMMARY, "last_updated": datetime.datetime.now().isoformat()}

    try:
        from netmiko import ConnectHandler
    except ImportError:
        raise RuntimeError("netmiko がインストールされていません。pip install netmiko を実行してください。")

    device = {
        "device_type": config["device_type"],
        "host":        config["host"],
        "username":    config["username"],
        "password":    config["password"],
        "port":        config.get("port", 22),
        "timeout":     20,
        "conn_timeout": 10,
    }

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

    device = {
        "device_type": config["device_type"],
        "host":        config["host"],
        "username":    config["username"],
        "password":    config["password"],
        "port":        config.get("port", 22),
        "timeout":     30,
    }

    with ConnectHandler(**device) as conn:
        if config["device_type"] == "juniper_junos":
            output = conn.send_command("show route protocol bgp", read_timeout=60)
        else:
            output = conn.send_command("show ip bgp", read_timeout=60)

    return parse_bgp_routes(output)
