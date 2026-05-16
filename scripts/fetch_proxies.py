#!/usr/bin/env python3
"""
极速版代理抓取与验证 —— 针对 GitHub Actions 优化，严格控制耗时。
"""
import asyncio
import aiohttp
import json
import re
import socket
import time
from typing import List, Dict, Tuple
from urllib.parse import urlparse

# ========== 配置 ==========
TEST_URL = "http://connectivitycheck.platform.hicloud.com/generate_204"
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=5)          # HTTP 验证 5 秒超时
MAX_CONCURRENT = 50                                    # 并发验证数
MAX_PER_SOURCE = 150                                 # 单个源最多抓多少条
MAX_HTTP_VERIFY = 100                                # 最多验证多少条 HTTP
MAX_SOCKS5_VERIFY = 50                               # 最多验证多少条 SOCKS5
MAX_HTTP_KEEP = 25                                   # 最终保留 HTTP 数
MAX_SOCKS5_KEEP = 15                                 # 最终保留 SOCKS5 数
OUTPUT_DIR = "docs"

SOURCES = {
    "proxyscrape_http": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&timeout=10000&country=all&proxy_format=protocolipport&format=json",
    "proxyscrape_socks5": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&timeout=10000&country=all&proxy_format=protocolipport&format=json",
    "github_http": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "github_socks5": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
}


def is_public_ip(ip: str) -> bool:
    """跳过内网/本地地址，确保不指向 127.0.0.1"""
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1])
        if first == 127 or first == 10:
            return False
        if first == 172 and 16 <= second <= 31:
            return False
        if first == 192 and second == 168:
            return False
        return True
    except Exception:
        return False


async def fetch_source(session: aiohttp.ClientSession, name: str, url: str) -> List[Dict[str, str]]:
    """从单个源抓取原始代理列表，带总体超时"""
    proxies = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                print(f"[源:{name}] HTTP {resp.status}")
                return proxies
            text = await resp.text()
    except asyncio.TimeoutError:
        print(f"[源:{name}] 请求超时(15s)")
        return proxies
    except Exception as e:
        print(f"[源:{name}] 请求失败: {e}")
        return proxies

    # ProxyScrape JSON
    if "proxyscrape" in name:
        try:
            data = json.loads(text)
            for item in data.get("proxies", [])[:MAX_PER_SOURCE]:
                ip = item.get("ip")
                port = item.get("port")
                protocol = item.get("protocol", "http")
                if ip and port and is_public_ip(ip):
                    proxies.append({"ip": ip, "port": str(port), "type": protocol.lower()})
        except json.JSONDecodeError:
            pass

    # GitHub raw txt
    else:
        proto = "http" if "http" in name else "socks5"
        count = 0
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):([0-9]{1,5})$", line)
            if m:
                ip, port = m.group(1), m.group(2)
                if is_public_ip(ip):
                    proxies.append({"ip": ip, "port": port, "type": proto})
                    count += 1
                    if count >= MAX_PER_SOURCE:
                        break

    print(f"[源:{name}] 抓取到 {len(proxies)} 个代理")
    return proxies


async def verify_http_proxy(session: aiohttp.ClientSession, proxy: Dict[str, str]) -> Tuple[bool, float]:
    """验证HTTP代理，返回(是否可用, 延迟ms)"""
    proxy_url = f"http://{proxy['ip']}:{proxy['port']}"
    start = time.time()
    try:
        async with session.get(
            TEST_URL,
            proxy=proxy_url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        ) as resp:
            latency = (time.time() - start) * 1000
            if resp.status in (200, 204):
                return True, latency
    except Exception:
        pass
    return False, 99999.0


async def verify_socks5_tcp(proxy: Dict[str, str]) -> Tuple[bool, float]:
    """
    极速版 SOCKS5 验证：只做 TCP 端口连通测试 + 简单发送 SOCKS5 握手首字节。
    完整 handshake 在 Actions 网络下容易卡住，改为轻量探测。
    """
    ip, port = proxy["ip"], int(proxy["port"])
    start = time.time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=socket.AF_INET),
            timeout=4
        )
        # 发送 SOCKS5 版本标识+无认证，看对方是否回 SOCKS5 应答
        writer.write(bytes([0x05, 0x01, 0x00]))
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2), timeout=3)
        writer.close()
        await writer.wait_closed()
        if len(resp) >= 2 and resp[0] == 0x05:
            latency = (time.time() - start) * 1000
            return True, latency
    except Exception:
        pass
    return False, 99999.0


async def main():
    all_proxies: List[Dict[str, str]] = []

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_source(session, name, url) for name, url in SOURCES.items()]
        results = await asyncio.gather(*tasks)
        for plist in results:
            all_proxies.extend(plist)

    # 去重
    seen = set()
    unique = []
    for p in all_proxies:
        key = (p["type"], p["ip"], p["port"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    all_proxies = unique
    print(f"去重后共 {len(all_proxies)} 个代理待验证")

    http_candidates = [p for p in all_proxies if p["type"] == "http"][:MAX_HTTP_VERIFY]
    socks5_candidates = [p for p in all_proxies if p["type"] == "socks5"][:MAX_SOCKS5_VERIFY]
    print(f"HTTP验证: {len(http_candidates)}, SOCKS5验证: {len(socks5_candidates)}")

    # 验证 HTTP
    valid_http = []
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def bounded_verify_http(p):
        async with sem:
            ok, lat = await verify_http_proxy(session, p)
            return p, ok, lat

    async with aiohttp.ClientSession() as session:
        tasks = [bounded_verify_http(p) for p in http_candidates]
        for p, ok, lat in await asyncio.gather(*tasks):
            if ok:
                p["latency"] = lat
                valid_http.append(p)

    # 验证 SOCKS5
    valid_socks5 = []

    async def bounded_verify_socks5(p):
        async with sem:
            ok, lat = await verify_socks5_tcp(p)
            return p, ok, lat

    tasks = [bounded_verify_socks5(p) for p in socks5_candidates]
    for p, ok, lat in await asyncio.gather(*tasks):
        if ok:
            p["latency"] = lat
            valid_socks5.append(p)

    # 排序截断
    valid_http.sort(key=lambda x: x["latency"])
    valid_socks5.sort(key=lambda x: x["latency"])
    valid_http = valid_http[:MAX_HTTP_KEEP]
    valid_socks5 = valid_socks5[:MAX_SOCKS5_KEEP]

    print(f"最终可用 — HTTP: {len(valid_http)}, SOCKS5: {len(valid_socks5)}")
    for p in valid_http[:5]:
        print(f"  [HTTP] {p['ip']}:{p['port']} ({p['latency']:.0f}ms)")
    for p in valid_socks5[:5]:
        print(f"  [SOCKS5] {p['ip']}:{p['port']} ({p['latency']:.0f}ms)")

    # 写入
    import os
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(f"{OUTPUT_DIR}/http_proxies.txt", "w") as f:
        for p in valid_http:
            f.write(f"{p['ip']}:{p['port']}\n")

    with open(f"{OUTPUT_DIR}/socks5_proxies.txt", "w") as f:
        for p in valid_socks5:
            f.write(f"{p['ip']}:{p['port']}\n")

    with open(f"{OUTPUT_DIR}/proxies.json", "w") as f:
        json.dump({"http": valid_http, "socks5": valid_socks5}, f, indent=2)

    print("代理列表已保存到 docs/ 目录")


if __name__ == "__main__":
    asyncio.run(main())
