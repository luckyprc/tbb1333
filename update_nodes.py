#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点聚合器（US解锁版 + HTTP速度测试）
- 保留美国（US）、日本（JP）、新加坡（SG）、德国（DE）及亚洲其他（不含CN）
- 增加HTTP层下载速度测试（>500KB/s保留）
- 目标：YouTube/Gemini/ChatGPT/Claude/Dola 可用
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

# HTTP下载速度阈值（KB/s），低于此值视为带宽不足
HTTP_SPEED_THRESHOLD = 500
HTTP_SPEED_TEST_SIZE = 1024 * 100  # 读取前100KB计算速度

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

# 封禁欧洲、南美、澳洲、俄罗斯等（保留US）
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

# 放行美国、亚洲、德国、法国
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
        resp = requests.get(url, timeout=5)
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


def http_speed_test(host: str, port: int) -> Optional[float]:
    """
    HTTP层下载速度测试（KB/s）。
    对节点的host:port直接发起HTTP GET，读取前100KB计算速度。
    注意：代理节点通常跑vmess/ss/trojan协议，此测试只能捕获
    带有HTTP伪装或nginx反代的节点，但这些节点通常带宽更好。
    """
    if not host or not port:
        return None
    try:
        url = f"http://{host}:{port}/"
        start = time.time()
        resp = requests.get(url, timeout=5, stream=True, allow_redirects=False)
        # 读取前100KB
        data = resp.raw.read(HTTP_SPEED_TEST_SIZE)
        elapsed = time.time() - start
        if elapsed > 0 and len(data) > 100:  # 至少收到100字节
            speed_kbps = (len(data) / 1024) / elapsed
            return round(speed_kbps, 2)
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


def process_single_node(node: str) -> Optional[Tuple[str, float, float, str, Optional[str]]]:
    """
    单节点完整处理：DNS解析 -> TCP延迟 -> HTTP速度
    返回: (node, tcp_lat, http_speed, host, ip) 或 None
    """
    host = extract_host_from_node(node)
    port = extract_port_from_node(node)
    if not host or not port:
        return None
    
    # DNS解析
    ip = get_ip_from_host(host)
    target = ip or host
    
    # TCP延迟测试
    tcp_lat = tcp_latency_test(target, port)
    if tcp_lat is None:
        return None
    
    # HTTP下载速度测试（对存活节点测带宽）
    http_speed = http_speed_test(host, port)
    
    return (node, tcp_lat, http_speed, host, ip)


def main():
    try:
        t_start = time.time()
        ensure_dir(OUTPUT_DIR)
        today = get_today_str()
        print(f"=== Start | {today} ===")

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

        # 3. 并发：DNS + TCP + HTTP速度
        passed_nodes: List[Tuple[str, float, float, str, Optional[str]]] = []
        
        print(f"[3] Testing {len(unique_nodes)} nodes...")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_single_node, node): node for node in unique_nodes}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        passed_nodes.append(result)
                except Exception:
                    pass
        
        print(f"[3] TCP ok: {len(passed_nodes)}")

        # 4. 地域过滤
        allowed_nodes: List[Tuple[str, float, float]] = []  # (node, tcp_lat, http_speed)
        pending: List[Tuple[str, float, float, str, Optional[str]]] = []
        
        for node, tcp_lat, http_speed, host, ip in passed_nodes:
            tld_result = check_tld(host)
            if tld_result is True:
                allowed_nodes.append((node, tcp_lat, http_speed))
                continue
            elif tld_result is False:
                continue
            pending.append((node, tcp_lat, http_speed, host, ip))
        
        if pending:
            print(f"[4] GeoIP: {len(pending)} pending...")
            cache: Dict[str, Optional[Dict]] = {}
            for node, tcp_lat, http_speed, host, ip in pending:
                if not ip:
                    continue
                data = cache.get(ip)
                if data is None and ip not in cache:
                    data = query_ip_region(ip)
                    cache[ip] = data
                if data and is_allowed_region(data):
                    allowed_nodes.append((node, tcp_lat, http_speed))
        
        print(f"[4] Region ok: {len(allowed_nodes)}")

        # 5. 按HTTP速度排序（速度高的在前），无速度数据的按TCP延迟排
        # 排序策略：有http_speed的优先，且>500KB/s的排最前
        def sort_key(item):
            node, tcp_lat, http_speed = item
            if http_speed and http_speed >= HTTP_SPEED_THRESHOLD:
                return (0, -http_speed)  # 第一梯队：高带宽，按速度降序
            elif http_speed:
                return (1, -http_speed)  # 第二梯队：有速度但不高
            else:
                return (2, tcp_lat)      # 第三梯队：只有TCP延迟
        
        allowed_nodes.sort(key=sort_key)

        # 6. 输出
        if allowed_nodes:
            node_text = "\n".join([n for n, _, _ in allowed_nodes])
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(node_text)
            # 打印前5个节点信息
            for i, (node, lat, speed) in enumerate(allowed_nodes[:5], 1):
                h = extract_host_from_node(node)
                flag = "🚀" if speed and speed >= HTTP_SPEED_THRESHOLD else ""
                print(f"  TOP{i}: {h} | TCP:{lat}ms | HTTP:{speed}KB/s {flag}")
            print(f"[OK] Output: {len(allowed_nodes)} nodes")
        else:
            print("[WARN] No nodes passed all filters.")
            open(OUTPUT_FILE, "w").close()

        print(f"[DONE] {round(time.time() - t_start, 1)}s")
        
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
