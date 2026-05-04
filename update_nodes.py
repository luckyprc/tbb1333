#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点聚合器（20秒极速版）
- 砍掉HTTP层测速（代理节点非HTTP服务，超时浪费生命）
- GeoIP查询改为16线程并发
- 保留美国/US、日本/JP、新加坡/SG、德国/DE及亚洲（不含CN）
- 只保留TCP延迟<599ms
"""

import base64
import json
import os
import re
import socket
import sys
import time
import traceback
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml


OUTPUT_DIR = "output"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "v2ray.txt")

TCP_LATENCY_THRESHOLD = 599
TCP_TIMEOUT = 2
DNS_TIMEOUT = 2
MAX_WORKERS = 64
GEO_WORKERS = 16  # GeoIP并发线程

ALLOWED_CC = {
    "US", "JP", "KR", "SG", "HK", "TW", "MY", "TH", "VN", "ID", "PH", "IN", "AE",
    "TR", "KH", "LA", "MM", "BD", "LK", "NP", "PK", "MN", "MO", "BN", "TL",
    "KZ", "KG", "UZ", "TJ", "TM", "GE", "AM", "AZ", "CY", "IL", "JO", "KW",
    "LB", "OM", "QA", "SA", "YE", "BH", "IQ", "IR", "PS", "SY", "AF", "BT", "MV", "IO",
    "DE", "FR"
}

ALLOWED_CNAMES = {
    "United States", "Japan", "Korea", "South Korea", "Republic of Korea", "Singapore",
    "Hong Kong", "Taiwan", "Malaysia", "Thailand", "Vietnam", "Indonesia",
    "Philippines", "India", "United Arab Emirates", "Turkey", "Cambodia",
    "Laos", "Myanmar", "Burma", "Bangladesh", "Sri Lanka", "Nepal", "Pakistan",
    "Mongolia", "Macao", "Macau", "Brunei", "Timor-Leste", "East Timor",
    "Kazakhstan", "Kyrgyzstan", "Uzbekistan", "Tajikistan", "Turkmenistan",
    "Georgia", "Armenia", "Azerbaijan", "Cyprus", "Israel", "Jordan", "Kuwait",
    "Lebanon", "Oman", "Qatar", "Saudi Arabia", "Yemen", "Bahrain", "Iraq",
    "Iran", "Palestine", "Syria", "Afghanistan", "Bhutan", "Maldives",
    "British Indian Ocean Territory", "Germany", "France"
}

BLOCKED_TLDS = set("""
.uk .co.uk .gb .ca .au .nz .ru .ua .by
.nl .it .es .pl .se .no .fi .dk .ch .at .be
.ie .pt .cz .hu .ro .sk .bg .hr .si .lt .lv
.ee .lu .mt .is .li .mc .sm .va .ad .mx .br
.ar .cl .co .pe .ve .ec .uy .py .bo .sr .gy
.gf .fk .gs .io .tk .ml .ga .cf .gq .st .sc
.lc .vc .ag .dm .kn .bb .gd .tt .jm .ht .bs
.cu .do .pr .vi .gu .mp .as .fm .pw .mh .nr
.ki .tv .to .ws .sb .vu .fj .pg .ck .nu .wf
.pn .ai .vg .ky .bm .tc .ms .gp .mq .re .yt
.pm .tf .pf .nc .ac .sh .cx .cc .hm .nf
""".split())

ALLOWED_TLDS = set("""
.us .de .fr .jp .kr .sg .hk .tw .my .th .vn .id
.ph .in .ae .tr .kh .la .mm .bd .lk .np .pk
.mn .mo .bn .tl .kz .kg .uz .tj .tm .ge .am
.az .il .jo .kw .lb .om .qa .sa .ye .bh .iq
.ir .ps .sy .af .bt .mv
""".split())

SOURCES = [
    "http://comm.cczzuu.top/node/{date}-v2ray.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/EternityAir",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
]

DATE_FMT = "%Y%m%d"


def get_today_str() -> str:
    return time.strftime(DATE_FMT, time.localtime())


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def fetch_url(url: str, retries: int = 2) -> Optional[str]:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0"}
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            if attempt == retries:
                return None
            time.sleep(1)
    return None


def decode_base64(data: str) -> str:
    try:
        data = data.strip()
        pad = 4 - len(data) % 4
        if pad != 4:
            data += "=" * pad
        return base64.b64decode(data).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_host_from_node(node_url: str) -> Optional[str]:
    try:
        if node_url.startswith("vmess://"):
            b64 = node_url[8:]
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += "=" * pad
            cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            return cfg.get("add") or cfg.get("host")
        elif node_url.startswith("ss://"):
            parsed = urllib.parse.urlparse(node_url)
            if parsed.hostname:
                return parsed.hostname
            b64_part = node_url[5:].split("#")[0].split("@")[0]
            decoded = decode_base64(b64_part)
            if "@" in decoded:
                return decoded.split("@")[1].split(":")[0]
        elif node_url.startswith("ssr://"):
            decoded = decode_base64(node_url[6:])
            parts = decoded.split(":")
            if len(parts) >= 2:
                return parts[0]
        elif node_url.startswith(("trojan://", "vless://")):
            parsed = urllib.parse.urlparse(node_url)
            return parsed.hostname
        return None
    except Exception:
        return None


def extract_port_from_node(node_url: str) -> Optional[int]:
    try:
        if node_url.startswith("vmess://"):
            b64 = node_url[8:]
            pad = 4 - len(b64) % 4
            if pad != 4:
                b64 += "=" * pad
            cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            return int(cfg.get("port", 0))
        elif node_url.startswith(("ss://", "trojan://", "vless://")):
            parsed = urllib.parse.urlparse(node_url)
            return parsed.port
        elif node_url.startswith("ssr://"):
            decoded = decode_base64(node_url[6:])
            parts = decoded.split(":")
            if len(parts) >= 2:
                return int(parts[1])
        return None
    except Exception:
        return None


def get_ip_from_host(host: str) -> Optional[str]:
    if not host:
        return None
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return host
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def check_tld(host: str) -> Optional[bool]:
    if not host:
        return None
    h = host.lower()
    for tld in BLOCKED_TLDS:
        if h.endswith(tld):
            return False
    for tld in ALLOWED_TLDS:
        if h.endswith(tld):
            return True
    return None


def query_ip_region(ip: str) -> Optional[Dict]:
    if not ip:
        return None
    if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "192.168.", "127.")):
        return None
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,query&lang=zh-CN"
        resp = requests.get(url, timeout=4)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return None


def is_allowed_region(region_data: Optional[Dict]) -> bool:
    if not region_data:
        return False
    cc = region_data.get("countryCode", "")
    cn = region_data.get("country", "")
    if cc in ALLOWED_CC:
        return True
    if cn in ALLOWED_CNAMES:
        return True
    return False


def tcp_latency_test(host: str, port: int) -> Optional[float]:
    if not host or not port:
        return None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TCP_TIMEOUT)
        start = time.time()
        result = sock.connect_ex((host, port))
        elapsed = (time.time() - start) * 1000
        sock.close()
        if result == 0 and elapsed < TCP_LATENCY_THRESHOLD:
            return round(elapsed, 2)
        return None
    except Exception:
        return None


def parse_subscribe_content(text: str) -> List[str]:
    nodes = []
    if not text:
        return nodes
    try:
        decoded = decode_base64(text)
        if decoded and ("://" in decoded):
            text = decoded
    except Exception:
        pass
    
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("vmess://", "ss://", "ssr://", "trojan://", "vless://")):
            nodes.append(line)
    
    if not nodes and ("proxies:" in text or "Proxy:" in text):
        try:
            data = yaml.safe_load(text)
            proxies = data.get("proxies", []) if isinstance(data, dict) else []
            for p in proxies:
                if not isinstance(p, dict):
                    continue
                proto = p.get("type", "").lower()
                if proto == "vmess":
                    cfg = {
                        "v": "2", "ps": p.get("name", "vmess"),
                        "add": p.get("server"), "port": str(p.get("port")),
                        "id": p.get("uuid"), "aid": str(p.get("alterId", 0)),
                        "scy": p.get("cipher", "auto"), "net": p.get("network", "tcp"),
                        "type": "none", "host": p.get("ws-opts", {}).get("headers", {}).get("Host", ""),
                        "path": p.get("ws-opts", {}).get("path", ""),
                        "tls": "tls" if p.get("tls") else ""
                    }
                    nodes.append("vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode())
                elif proto == "ss":
                    userinfo = base64.b64encode(f"{p.get('cipher')}:{p.get('password')}".encode()).decode()
                    nodes.append(f"ss://{userinfo}@{p.get('server')}:{p.get('port')}")
                elif proto == "trojan":
                    nodes.append(f"trojan://{p.get('password')}@{p.get('server')}:{p.get('port')}?sni={p.get('sni', '')}")
        except Exception:
            pass
    return nodes


def get_source_urls() -> List[str]:
    today = get_today_str()
    year = time.strftime("%Y", time.localtime())
    month = time.strftime("%m", time.localtime())
    urls = [src.replace("{date}", today) for src in SOURCES]
    for i in range(5):
        urls.append(f"https://node.freeclashnode.com/uploads/{year}/{month}/{i}-{today}.txt")
    return urls


def process_single_node(node: str) -> Optional[Tuple[str, float, str, Optional[str]]]:
    host = extract_host_from_node(node)
    port = extract_port_from_node(node)
    if not host or not port:
        return None
    ip = get_ip_from_host(host)
    target = ip or host
    lat = tcp_latency_test(target, port)
    if lat is None:
        return None
    return (node, lat, host, ip)


def main():
    try:
        t_start = time.time()
        ensure_dir(OUTPUT_DIR)
        today = get_today_str()
        print(f"=== Start | {today} ===")

        # 1. 抓取
        all_nodes: List[str] = []
        for url in get_source_urls():
            content = fetch_url(url)
            if content:
                all_nodes.extend(parse_subscribe_content(content))

        print(f"[1] Fetch: {len(all_nodes)}")
        if not all_nodes:
            open(OUTPUT_FILE, "w").close()
            return

        # 2. 去重
        seen: Set[str] = set()
        unique_nodes: List[str] = []
        for node in all_nodes:
            host = extract_host_from_node(node)
            port = extract_port_from_node(node)
            proto = node.split("://")[0] if "://" in node else "unknown"
            fp = f"{proto}://{host}:{port}"
            if fp not in seen and host and port:
                seen.add(fp)
                unique_nodes.append(node)
        
        print(f"[2] Dedup: {len(unique_nodes)}")

        # 3. 并发DNS+TCP（64线程）
        tcp_passed: List[Tuple[str, float, str, Optional[str]]] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_single_node, node): node for node in unique_nodes}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        tcp_passed.append(result)
                except Exception:
                    pass
        
        print(f"[3] TCP ok: {len(tcp_passed)}")
        if not tcp_passed:
            open(OUTPUT_FILE, "w").close()
            return

        # 4. 地域过滤：TLD硬规则 + GeoIP并发查询
        allowed_nodes: List[Tuple[str, float]] = []
        pending: List[Tuple[str, float, str, Optional[str]]] = []
        
        for node, lat, host, ip in tcp_passed:
            tld_result = check_tld(host)
            if tld_result is True:
                allowed_nodes.append((node, lat))
                continue
            elif tld_result is False:
                continue
            pending.append((node, lat, host, ip))
        
        if pending:
            print(f"[4] GeoIP: {len(pending)} pending...")
            
            # 先收集所有需要查询的唯一IP
            unique_ips: Set[str] = set()
            ip_to_nodes: Dict[str, List[Tuple[str, float, str]]] = {}
            for node, lat, host, ip in pending:
                if ip:
                    unique_ips.add(ip)
                    ip_to_nodes.setdefault(ip, []).append((node, lat, host))
            
            # 并发查询ip-api.com（16线程）
            region_cache: Dict[str, Optional[Dict]] = {}
            with ThreadPoolExecutor(max_workers=GEO_WORKERS) as executor:
                future_map = {executor.submit(query_ip_region, ip): ip for ip in unique_ips}
                for future in as_completed(future_map):
                    ip = future_map[future]
                    try:
                        region_cache[ip] = future.result()
                    except Exception:
                        region_cache[ip] = None
            
            # 根据查询结果过滤
            for ip, nodes_list in ip_to_nodes.items():
                data = region_cache.get(ip)
                if data and is_allowed_region(data):
                    for node, lat, host in nodes_list:
                        allowed_nodes.append((node, lat))
        
        print(f"[4] Region ok: {len(allowed_nodes)}")

        # 5. 输出（按TCP延迟升序）
        if allowed_nodes:
            allowed_nodes.sort(key=lambda x: x[1])
            node_text = "\n".join([n for n, _ in allowed_nodes])
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(node_text)
            print(f"[OK] Output: {len(allowed_nodes)} nodes")
        else:
            print("[WARN] No nodes in allowed regions.")
            open(OUTPUT_FILE, "w").close()

        print(f"[DONE] {round(time.time() - t_start, 1)}s")
        
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
