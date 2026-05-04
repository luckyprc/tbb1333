#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点聚合器（纯TLD极速版）
- 无GeoIP查询，无ip-api.com
- TLD硬规则：明确放行/封禁，其余.com/.net/.org等通用后缀直接放行
- DNS+TCP 64线程并发
- 目标：10-15秒完成
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

# 明确封禁的TLD（欧洲、南美、澳洲、俄罗斯等）
BLOCKED_TLDS = set("""
.uk .co.uk .gb .ca .au .nz .ru .ua .by
.nl .it .es .pl .se .no .fi .dk .ch .at .be
.ie .pt .cz .hu .ro .sk .bg .hr .si .lt .lv
.ee .lu .mt .is .li .mc .sm .va .ad .mx .br
.ar .cl .co .pe .ve .ec .uy .py .bo .sr .gy
.gf .fk .gs .tk .ml .ga .cf .gq .st .sc
.lc .vc .ag .dm .kn .bb .gd .tt .jm .ht .bs
.cu .do .pr .vi .gu .mp .as .fm .pw .mh .nr
.ki .tv .to .ws .sb .vu .fj .pg .ck .nu .wf
.pn .ai .vg .ky .bm .tc .ms .gp .mq .re .yt
.pm .tf .pf .nc .ac .sh .cx .cc .hm .nf
""".split())

# 明确放行的TLD（美国、亚洲、德国、法国）
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


def check_tld(host: str) -> bool:
    """
    TLD硬规则：
    - 命中BLOCKED → False（丢弃）
    - 命中ALLOWED → True（放行）
    - 其余.com/.net/.org/.xyz/.cloud/.top/.world/.ltd等通用后缀 → True（放行，保留美国节点）
    """
    if not host:
        return False
    h = host.lower()
    for tld in BLOCKED_TLDS:
        if h.endswith(tld):
            return False
    for tld in ALLOWED_TLDS:
        if h.endswith(tld):
            return True
    # 通用后缀（.com/.net/.org/.xyz/.cloud/.shop/.online/.live/.site/.space等）直接放行
    return True


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


def process_single_node(node: str) -> Optional[Tuple[str, float, str]]:
    """
    DNS解析 -> TCP测试
    返回: (node, latency, host) 或 None
    """
    host = extract_host_from_node(node)
    port = extract_port_from_node(node)
    if not host or not port:
        return None
    ip = get_ip_from_host(host)
    target = ip or host
    lat = tcp_latency_test(target, port)
    if lat is None:
        return None
    return (node, lat, host)


def main():
    try:
        t_start = time.time()
        ensure_dir(OUTPUT_DIR)
        today = get_today_str()
        print(f"=== Start | {today} ===", flush=True)

        # 1. 抓取
        all_nodes: List[str] = []
        for url in get_source_urls():
            content = fetch_url(url)
            if content:
                all_nodes.extend(parse_subscribe_content(content))

        print(f"[1] Fetch: {len(all_nodes)}", flush=True)
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
        
        print(f"[2] Dedup: {len(unique_nodes)}", flush=True)

        # 3. 并发DNS+TCP
        tcp_passed: List[Tuple[str, float, str]] = []
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_single_node, node): node for node in unique_nodes}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        tcp_passed.append(result)
                except Exception:
                    pass
        
        print(f"[3] TCP ok: {len(tcp_passed)}", flush=True)
        if not tcp_passed:
            open(OUTPUT_FILE, "w").close()
            return

        # 4. 纯TLD硬过滤（无GeoIP，无ip-api.com）
        allowed_nodes: List[Tuple[str, float]] = []
        dropped = 0
        
        for node, lat, host in tcp_passed:
            if check_tld(host):
                allowed_nodes.append((node, lat))
            else:
                dropped += 1
        
        print(f"[4] TLD pass: {len(allowed_nodes)} | dropped: {dropped}", flush=True)

        # 5. 输出（按TCP延迟升序）
        if allowed_nodes:
            allowed_nodes.sort(key=lambda x: x[1])
            node_text = "\n".join([n for n, _ in allowed_nodes])
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(node_text)
            print(f"[OK] Output: {len(allowed_nodes)} nodes", flush=True)
        else:
            print("[WARN] No nodes passed TLD filter.", flush=True)
            open(OUTPUT_FILE, "w").close()

        print(f"[DONE] {round(time.time() - t_start, 1)}s", flush=True)
        
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
