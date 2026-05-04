#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点聚合器（诊断版）
- 增加详细过滤日志
- 增加保底机制：如果全部过滤为空，输出原始去重节点（方便排查）
"""

import base64
import json
import os
import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple

import requests
import yaml


OUTPUT_DIR = "output"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "v2ray.txt")

# ========== 诊断开关 ==========
# 设为 True 则保留所有节点（只去重），用于确认源站是否有数据
DEBUG_SKIP_ALL_FILTERS = False

TCP_LATENCY_THRESHOLD = 250
HTTP_LATENCY_THRESHOLD = 250
HTTP_CHECK_URL = "http://connectivitycheck.platform.hicloud.com/generate_204"
TCP_TIMEOUT = 3
MAX_WORKERS = 64
IP_QUERY_DELAY = 1.5

ALLOWED_CC = {
    "JP", "KR", "SG", "HK", "TW", "MY", "TH", "VN", "ID", "PH", "IN", "AE",
    "TR", "KH", "LA", "MM", "BD", "LK", "NP", "PK", "MN", "MO", "BN", "TL",
    "KZ", "KG", "UZ", "TJ", "TM", "GE", "AM", "AZ", "CY", "IL", "JO", "KW",
    "LB", "OM", "QA", "SA", "YE", "BH", "IQ", "IR", "PS", "SY", "AF", "BT", "MV", "IO",
    "DE", "FR"
}

ALLOWED_CNAMES = {
    "Japan", "Korea", "South Korea", "Republic of Korea", "Singapore",
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

BLOCKED_TLDS = {
    '.uk', '.co.uk', '.gb', '.us', '.ca', '.au', '.nz', '.ru', '.ua', '.by',
    '.nl', '.it', '.es', '.pl', '.se', '.no', '.fi', '.dk', '.ch', '.at', '.be',
    '.ie', '.pt', '.cz', '.hu', '.ro', '.sk', '.bg', '.hr', '.si', '.lt', '.lv',
    '.ee', '.lu', '.mt', '.is', '.li', '.mc', '.sm', '.va', '.ad', '.mx', '.br',
    '.ar', '.cl', '.co', '.pe', '.ve', '.ec', '.uy', '.py', '.bo', '.sr', '.gy',
    '.gf', '.fk', '.gs', '.io', '.tk', '.ml', '.ga', '.cf', '.gq', '.st', '.sc',
    '.lc', '.vc', '.ag', '.dm', '.kn', '.bb', '.gd', '.tt', '.jm', '.ht', '.bs',
    '.cu', '.do', '.pr', '.vi', '.gu', '.mp', '.as', '.fm', '.pw', '.mh', '.nr',
    '.ki', '.tv', '.to', '.ws', '.sb', '.vu', '.fj', '.pg', '.ck', '.nu', '.wf',
    '.pn', '.ai', '.vg', '.ky', '.bm', '.tc', '.ms', '.gp', '.mq', '.re', '.yt',
    '.pm', '.tf', '.pf', '.nc', '.ac', '.sh', '.cx', '.cc', '.hm', '.nf'
}

ALLOWED_TLDS = {
    '.de', '.fr', '.jp', '.kr', '.sg', '.hk', '.tw', '.my', '.th', '.vn', '.id',
    '.ph', '.in', '.ae', '.tr', '.kh', '.la', '.mm', '.bd', '.lk', '.np', '.pk',
    '.mn', '.mo', '.bn', '.tl', '.kz', '.kg', '.uz', '.tj', '.tm', '.ge', '.am',
    '.az', '.il', '.jo', '.kw', '.lb', '.om', '.qa', '.sa', '.ye', '.bh', '.iq',
    '.ir', '.ps', '.sy', '.af', '.bt', '.mv'
}

SOURCES = [
    "http://comm.cczzuu.top/node/{date}-v2ray.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/EternityAir",
    "https://raw.githubusercontent.com/pojiezhiyuanjun/freev2/master/{date}.txt",
    "https://raw.githubusercontent.com/Fukki-Z/nodefree/main/{date}.txt",
    "https://raw.githubusercontent.com/FiFier/v2rayShare/main/{date}.txt",
    "https://raw.githubusercontent.com/colatiger/v2ray-nodes/master/{date}.txt",
    "https://raw.githubusercontent.com/ssrsub/ssr/master/{date}.txt",
    "https://raw.githubusercontent.com/iwxf/free-v2ray/master/{date}.txt",
    "https://raw.githubusercontent.com/ldir92664/Vmess-Actions/main/{date}.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/{date}.txt",
    "https://raw.githubusercontent.com/wrfree/free/main/{date}.txt",
    "https://raw.githubusercontent.com/anaer/Sub/main/{date}.txt",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/misersun/config003/main/{date}.txt",
    "https://clash.221207.xyz/pubclashyaml",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/jikelonglie/meskell/master/{date}.txt",
    "https://raw.githubusercontent.com/MOnday9907/v2ray/master/{date}.txt",
    "https://raw.githubusercontent.com/Jia-Pingwa/free-v2ray-merge/master/{date}.txt",
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
        except Exception as e:
            if attempt == retries:
                print(f"[ERR] Fetch failed: {url} -> {e}")
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
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


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
        resp = requests.get(url, timeout=6)
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


def http_latency_test() -> Optional[float]:
    try:
        start = time.time()
        resp = requests.get(HTTP_CHECK_URL, timeout=5)
        elapsed = (time.time() - start) * 1000
        if resp.status_code == 204 and elapsed < HTTP_LATENCY_THRESHOLD:
            return round(elapsed, 2)
        return None
    except Exception:
        return None


def parse_subscribe_content(text: str) -> List[str]:
    nodes = []
    if not text:
        return nodes
    decoded = decode_base64(text)
    if decoded and ("://" in decoded):
        text = decoded
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
        except Exception as e:
            print(f"[WARN] YAML parse error: {e}")
    return nodes


def get_source_urls() -> List[str]:
    today = get_today_str()
    return [src.replace("{date}", today) for src in SOURCES]


# ==================== 主流程 ====================

def main():
    ensure_dir(OUTPUT_DIR)
    today = get_today_str()
    print(f"=== Node Aggregator Started | Date: {today} ===")

    # 调试模式：跳过所有过滤，只保留去重
    if DEBUG_SKIP_ALL_FILTERS:
        print("[DEBUG] DEBUG_SKIP_ALL_FILTERS = True, skipping all filters!")

    # 1. 抓取
    all_nodes: List[str] = []
    for url in get_source_urls():
        print(f"[FETCH] {url}")
        content = fetch_url(url)
        if content:
            nodes = parse_subscribe_content(content)
            print(f"  -> Got {len(nodes)} nodes")
            all_nodes.extend(nodes)
        else:
            print(f"  -> Failed or empty")

    print(f"[INFO] Total raw nodes: {len(all_nodes)}")
    if not all_nodes:
        print("[WARN] No nodes fetched, aborting.")
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
    print(f"[INFO] After dedup: {len(unique_nodes)}")

    # 调试模式：直接输出去重后的节点
    if DEBUG_SKIP_ALL_FILTERS:
        node_text = "\n".join(unique_nodes)
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(node_text)
        print(f"[DEBUG] Output {len(unique_nodes)} nodes without filtering.")
        return

    # 3. TCP 延迟测试
    tcp_passed: List[Tuple[str, float]] = []
    node_meta = []
    for node in unique_nodes:
        host = extract_host_from_node(node)
        port = extract_port_from_node(node)
        ip = get_ip_from_host(host) if host else None
        if host and port:
            node_meta.append((node, host, ip, port))

    print(f"[TEST] TCP latency testing {len(node_meta)} nodes (threshold {TCP_LATENCY_THRESHOLD}ms)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_map = {}
        for node, host, ip, port in node_meta:
            target = ip or host
            future = executor.submit(tcp_latency_test, target, port)
            future_map[future] = (node, host, ip, port)
        for future in as_completed(future_map):
            node, host, ip, port = future_map[future]
            lat = future.result()
            if lat is not None:
                tcp_passed.append((node, lat))
            else:
                print(f"  [DROP-TCP] {host}:{port} -> timeout or >{TCP_LATENCY_THRESHOLD}ms")

    print(f"[INFO] After TCP latency filter: {len(tcp_passed)}")
    if not tcp_passed:
        print("[WARN] No nodes passed TCP latency test.")
        # 保底：输出去重节点供排查
        print("[FALLBACK] Writing deduped nodes for diagnosis...")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join([n for n in unique_nodes]))
        return

    # 4. HTTP 延迟门槛
    print(f"[TEST] HTTP check ({HTTP_CHECK_URL}, threshold {HTTP_LATENCY_THRESHOLD}ms)...")
    http_lat = http_latency_test()
    if http_lat is None:
        print(f"[WARN] HTTP check failed (runner to hicloud >{HTTP_LATENCY_THRESHOLD}ms or timeout).")
        print("[FALLBACK] Writing TCP-passed nodes for diagnosis...")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join([n for n, _ in tcp_passed]))
        return
    print(f"[OK] HTTP baseline: {http_lat}ms")

    # 5. 地域过滤
    print(f"[GEO] Filtering regions (Asia w/o CN + DE/FR only)...")
    
    allowed_nodes: List[Tuple[str, float]] = []
    pending_nodes: List[Tuple[str, float, str, Optional[str]]] = []
    
    for node, tcp_lat in tcp_passed:
        host = extract_host_from_node(node)
        tld_result = check_tld(host)
        if tld_result is True:
            print(f"  [PASS-TLD] {host} -> allowed TLD")
            allowed_nodes.append((node, tcp_lat))
            continue
        elif tld_result is False:
            print(f"  [BLOCK-TLD] {host} -> blocked TLD")
            continue
        
        ip = get_ip_from_host(host) if host else None
        pending_nodes.append((node, tcp_lat, host or "?", ip))
    
    if pending_nodes:
        print(f"[GEO-IP] Need to query {len(pending_nodes)} IPs...")
        region_cache: Dict[str, Optional[Dict]] = {}
        
        for node, tcp_lat, host, ip in pending_nodes:
            if not ip:
                print(f"  [BLOCK-DNS] {host} -> DNS resolve failed")
                continue
            
            if ip in region_cache:
                data = region_cache[ip]
            else:
                data = query_ip_region(ip)
                region_cache[ip] = data
                time.sleep(IP_QUERY_DELAY)
            
            if data:
                cc = data.get("countryCode", "?")
                cn = data.get("country", "?")
                if is_allowed_region(data):
                    print(f"  [PASS-IP] {host} ({ip}) -> {cn} ({cc})")
                    allowed_nodes.append((node, tcp_lat))
                else:
                    print(f"  [BLOCK-IP] {host} ({ip}) -> {cn} ({cc})")
            else:
                print(f"  [BLOCK-UNK] {host} ({ip}) -> IP query failed (rate limit?)")
    
    print(f"[INFO] After region filter: {len(allowed_nodes)}")

    # 6. 输出
    if allowed_nodes:
        allowed_nodes.sort(key=lambda x: x[1])
        node_text = "\n".join([n for n, _ in allowed_nodes])
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write(node_text)
        print(f"[OK] Output: {OUTPUT_FILE} | {len(allowed_nodes)} nodes")
    else:
        print("[WARN] No nodes in allowed regions.")
        print("[FALLBACK] Writing TCP-passed nodes for diagnosis...")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join([n for n, _ in tcp_passed]))


if __name__ == "__main__":
    main()
