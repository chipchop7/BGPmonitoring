import re
from typing import List, Dict, Any, Optional, Tuple


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


# (metric_col, locprf_col, weight_col, path_col, nexthop_col)
_Cols = Tuple[int, int, int, int, int]


def _find_header_cols(output: str) -> Optional[_Cols]:
    """ヘッダー行から列開始位置を返す。nexthop_col は継続行オフセット計算に使う。"""
    for line in output.splitlines():
        if 'Metric' in line and 'Weight' in line and 'Path' in line:
            try:
                mc  = line.index('Metric')
                wc  = line.index('Weight')
                pc  = line.index('Path')
                lc  = line.index('LocPrf') if 'LocPrf' in line else mc + (wc - mc) // 2
                nhc = line.index('Next Hop') if 'Next Hop' in line else mc
                return mc, lc, wc, pc, nhc
            except ValueError:
                pass
    return None


# FRR/VyOS ステータスコード（RPKI: V/I/N, unsorted: u を含む）
_ROUTE_START = re.compile(
    r'^[ *>=sSdh?iruRSmbVINU]+'
    r'\s+(\d{1,3}(?:\.\d{1,3}){3}/\d+|[0-9a-fA-F:]+/\d+)'
)


def _col(line: str, a: int, b: int) -> str:
    a = max(a, 0)
    b = max(b, 0)
    return line[a:b].strip() if len(line) > a else ''


def _parse_bgp_table(output: str) -> List[Dict]:
    """
    FRR/VyOS BGP テーブルをパース。
    - マルチライン形式（プレフィックスと属性が別行）に対応
    - Metric/LocPrf が空白カラムでも正確に取得（列位置ベース）
    - 継続行のインデントがヘッダーの Next Hop 列とずれる場合はオフセット補正
    """
    cols  = _find_header_cols(output)
    lines = output.splitlines()
    routes: List[Dict] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        m = _ROUTE_START.match(line)
        if not m:
            i += 1
            continue

        prefix        = m.group(1)
        after_prefix  = line[m.end():]
        nh_m          = re.match(r'\s+(\S+)', after_prefix)
        is_cont       = False
        nh_actual_col = 0

        if nh_m:
            # 1行形式: ネクストホップが同じ行にある
            nexthop   = nh_m.group(1)
            attr_line = line
        elif i + 1 < len(lines) and re.match(r'^\s{10,}\S', lines[i + 1]):
            # マルチライン形式: ネクストホップ以降が次行
            nh_m2 = re.match(r'^\s+(\S+)', lines[i + 1])
            if not nh_m2:
                i += 1
                continue
            nexthop       = nh_m2.group(1)
            attr_line     = lines[i + 1]
            is_cont       = True
            nh_actual_col = len(lines[i + 1]) - len(lines[i + 1].lstrip())
            i += 1  # 継続行を消費
        else:
            i += 1
            continue

        if cols:
            mc, lc, wc, pc, nhc = cols
            if is_cont:
                # 継続行はヘッダーの Next Hop 列と実際のインデントが異なるため補正
                offset = nh_actual_col - nhc
                mc += offset; lc += offset; wc += offset; pc += offset
            metric    = _col(attr_line, mc, lc)
            locprf    = _col(attr_line, lc, wc)
            weight    = _col(attr_line, wc, pc)
            path_orig = attr_line[max(0, pc):].strip() if len(attr_line) > max(0, pc) else ''
        else:
            # ヘッダーなし環境向け正規表現フォールバック
            rm = re.search(
                r'\s+(\d+)\s+(\d+)\s+(\d+)\s+([\d\s]*?)([ie?])\s*$',
                attr_line)
            if not rm:
                i += 1
                continue
            metric, locprf, weight = rm.group(1), rm.group(2), rm.group(3)
            path_orig = rm.group(4).strip() + rm.group(5)

        origin_m = re.search(r'([ie?])\s*$', path_orig)
        if not origin_m:
            i += 1
            continue
        origin  = origin_m.group(1)
        as_path = path_orig[:origin_m.start()].strip()

        routes.append({
            "prefix":     prefix,
            "next_hop":   nexthop,
            "metric":     metric or "0",
            "local_pref": locprf or "",
            "weight":     weight or "0",
            "as_path":    as_path,
            "origin":     origin,
        })
        i += 1

    return routes


def parse_peer_routes(output: str) -> List[Dict]:
    return _parse_bgp_table(output)


def parse_bgp_routes(output: str) -> List[Dict]:
    return _parse_bgp_table(output)


def parse_bgp_neighbor_detail(output: str) -> Dict[str, Any]:
    """show bgp neighbors X の出力を解析（FRR/VyOS・Cisco IOS 共通）。"""
    d: Dict[str, Any] = {}

    def _find(pattern: str, default=None, group: int = 1, flags: int = 0):
        m = re.search(pattern, output, flags)
        return m.group(group) if m else default

    # BGP state + uptime
    m = re.search(r'BGP state\s*=\s*(\w+)(?:,\s*up for\s*(\S+))?', output, re.IGNORECASE)
    d['state']  = m.group(1) if m else '—'
    d['uptime'] = m.group(2) if (m and m.group(2)) else '—'

    # Remote router ID
    d['remote_router_id'] = _find(r'remote router ID\s+(\S+)', '—')

    # Hold time / Keepalive
    m = re.search(r'[Hh]old time is\s+(\d+)[^,\n]*,\s*[Kk]eepalive interval is\s+(\d+)', output)
    d['hold_time'] = int(m.group(1)) if m else None
    d['keepalive'] = int(m.group(2)) if m else None

    # 接続確立 / ドロップ回数
    m = re.search(r'Connections established\s+(\d+);\s*dropped\s+(\d+)', output)
    d['conn_established'] = int(m.group(1)) if m else 0
    d['conn_dropped']     = int(m.group(2)) if m else 0

    # 最終リセット
    m = re.search(r'[Ll]ast reset\s+(\S+)(?:[,\s]+(?:due to\s+|reason:\s*)?(.+))?', output)
    if m:
        d['last_reset_time']   = m.group(1)
        reason = (m.group(2) or '').strip().rstrip(',').strip()
        d['last_reset_reason'] = reason or '—'
    else:
        d['last_reset_time']   = '—'
        d['last_reset_reason'] = '—'

    # メッセージ統計（Sent / Rcvd 列）
    m = re.search(r'Updates:\s+(\d+)\s+(\d+)', output)
    d['updates_sent'] = int(m.group(1)) if m else 0
    d['updates_rcvd'] = int(m.group(2)) if m else 0

    m = re.search(r'Keepalives:\s+(\d+)\s+(\d+)', output)
    d['keepalives_sent'] = int(m.group(1)) if m else 0
    d['keepalives_rcvd'] = int(m.group(2)) if m else 0

    # Local / Foreign ホスト・ポート
    m = re.search(r'Local host:\s+(\S+),\s*Local port:\s+(\d+)', output)
    d['local_host'] = m.group(1) if m else '—'
    d['local_port'] = int(m.group(2)) if m else None

    m = re.search(r'Foreign host:\s+(\S+),\s*Foreign port:\s+(\d+)', output)
    d['foreign_host'] = m.group(1) if m else '—'
    d['foreign_port'] = int(m.group(2)) if m else None

    # ネゴシエーション済みケーパビリティ
    caps = []
    for pattern, label in [
        (r'4.?[Bb]yte AS.*?(?:advertised and received|enabled)',       '4-byte AS'),
        (r'[Rr]oute [Rr]efresh.*?(?:advertised and received|enabled)', 'Route Refresh'),
        (r'[Gg]raceful [Rr]estart.*?(?:advertised and received)',      'Graceful Restart'),
        (r'[Aa]ddress [Ff]amily IPv4 Unicast.*?advertised',            'IPv4 Unicast'),
        (r'[Aa]ddress [Ff]amily IPv6 Unicast.*?advertised',            'IPv6 Unicast'),
        (r'Add.?[Pp]ath.*?advertised',                                 'Add-Path'),
        (r'Extended [Mm]essage.*?advertised',                          'Extended Message'),
        (r'[Ee]nhanced [Rr]oute [Rr]efresh.*?advertised',             'Enhanced RR'),
    ]:
        if re.search(pattern, output):
            caps.append(label)
    d['capabilities'] = caps

    # 受付プレフィックス数
    m = re.search(r'(\d+)\s+accepted prefixes?', output)
    if not m:
        m = re.search(r'Accepted prefix count:\s+(\d+)', output)
    d['accepted_prefixes'] = int(m.group(1)) if m else None

    return d
