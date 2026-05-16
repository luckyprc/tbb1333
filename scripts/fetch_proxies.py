#!/usr/bin/env python3
"""
从多个公开代理池抓取 HTTP/SOCKS5 代理，并发验证可用性，
输出验证通过的代理列表供 PAC 生成器使用。
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
TEST_TIMEOUT = aiohttp.ClientTimeout(total=8)
MAX_CONCURRENT = 80          # 并发验证数
MAX_HTTP_PROXIES = 30        # 最终保留的HTTP代理数
MAX_SOCKS5_PROXIES = 20      # 最终保留的SOCKS5代理数
OUTPUT_DIR = "docs"

# 代理源列表
SOURCES = {
    "proxyscrape_http": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&timeout=10000&country=all&proxy_format=protocolipport&format=json",
    "proxyscrape_socks5": "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&timeout=10000&country=all&proxy_format=protocolipport&format=json",
    "databay_mixed": "https://databay.com/api/v1/proxy-list?protocol=http,socks5&anonymity=elite&limit=300",
    "github_http": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "github_socks5": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
}


async def fetch_source(session: aiohttp.ClientSession, name: str, url: str) -> List[Dict[str, str]]:
    """从单个源抓取原始代理列表"""
    proxies = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            if resp.status != 200:
                print(f"[源:{name}] HTTP {resp.status}")
                return proxies
            text = await resp.text()
    except Exception as e:
        print(f"[源:{name}] 请求失败: {e}")
        return proxies

    # ProxyScrape JSON
    if "proxyscrape" in name and "json" in url:
        try:
            data = json.loads(text)
            for item in data.get("proxies", []):
                ip = item.get("ip")
                port = item.get("port")
                protocol = item.get("protocol", "http")
                if ip and port:
                    proxies.append({"ip": ip, "port": str(port), "type": protocol.lower()})
        except json.JSONDecodeError:
            pass

    # Databay JSON
    elif "databay" in name:
        try:
            data = json.loads(text)
            for item in data.get("data", []):
                ip = item.get("ip")
                port = item.get("port")
                protocol = item.get("protocol", "http")
                if ip and port:
                    proxies.append({"ip": ip, "port": str(port), "type": protocol.lower()})
        except json.JSONDecodeError:
            pass

    # GitHub raw txt (ip:port 每行一个)
    else:
        proto = "http" if "http" in name else "socks5"
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 匹配 IP:PORT
            m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):([0-9]{1,5})$", line)
            if m:
                proxies.append({"ip": m.group(1), "port": m.group(2), "type": proto})

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
            timeout=TEST_TIMEOUT,
            allow_redirects=False,
        ) as resp:
            latency = (time.time() - start) * 1000
            # 204 或 200 都算成功
            if resp.status in (200, 204):
                return True, latency
    except Exception:
        pass
    return False, 99999.0


async def verify_socks5_proxy(proxy: Dict[str, str]) -> Tuple[bool, float]:
    """验证SOCKS5代理，使用底层socket测试TCP连通+简单HTTP请求"""
    ip, port = proxy["ip"], int(proxy["port"])
    start = time.time()
    try:
        # 第一阶段：TCP连通性测试
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=5
        )
        # 第二阶段：发送SOCKS5握手
        writer.write(bytes([0x05, 0x01, 0x00]))  # ver 5, 1 auth method, no auth
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2), timeout=3)
        if len(resp) < 2 or resp[0] != 0x05 or resp[1] != 0x00:
            writer.close()
            await writer.wait_closed()
            return False, 99999.0

        # 第三阶段：请求连接目标 (CONNECT to test_url host:80)
        host = urlparse(TEST_URL).hostname
        host_bytes = host.encode()
        req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) + host_bytes + bytes([0x00, 0x50])  # port 80
        writer.write(req)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(10), timeout=5)
        writer.close()
        await writer.wait_closed()

        if len(resp) >= 2 and resp[1] == 0x00:
            latency = (time.time() - start) * 1000
            return True, latency
    except Exception:
        pass
    return False, 99999.0


async def main():
    all_proxies: List[Dict[str, str]] = []

    # 1. 抓取
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

    http_proxies = [p for p in all_proxies if p["type"] == "http"]
    socks5_proxies = [p for p in all_proxies if p["type"] == "socks5"]
    print(f"HTTP待验证: {len(http_proxies)}, SOCKS5待验证: {len(socks5_proxies)}")

    # 2. 验证 HTTP
    valid_http = []
    async with aiohttp.ClientSession() as session:
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def bounded_verify_http(p):
            async with sem:
                ok, lat = await verify_http_proxy(session, p)
                return p, ok, lat

        tasks = [bounded_verify_http(p) for p in http_proxies]
        for p, ok, lat in await asyncio.gather(*tasks):
            if ok:
                p["latency"] = lat
                valid_http.append(p)
                print(f"  [HTTP OK] {p['ip']}:{p['port']} ({lat:.0f}ms)")

    # 3. 验证 SOCKS5
    valid_socks5 = []
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def bounded_verify_socks5(p):
        async with sem:
            ok, lat = await verify_socks5_proxy(p)
            return p, ok, lat

    tasks = [bounded_verify_socks5(p) for p in socks5_proxies]
    for p, ok, lat in await asyncio.gather(*tasks):
        if ok:
            p["latency"] = lat
            valid_socks5.append(p)
            print(f"  [SOCKS5 OK] {p['ip']}:{p['port']} ({lat:.0f}ms)")

    # 4. 排序并截断
    valid_http.sort(key=lambda x: x["latency"])
    valid_socks5.sort(key=lambda x: x["latency"])
    valid_http = valid_http[:MAX_HTTP_PROXIES]
    valid_socks5 = valid_socks5[:MAX_SOCKS5_PROXIES]

    print(f"\n最终可用 — HTTP: {len(valid_http)}, SOCKS5: {len(valid_socks5)}")

    # 5. 写入文件
    import os
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(f"{OUTPUT_DIR}/http_proxies.txt", "w") as f:
        for p in valid_http:
            f.write(f"{p['ip']}:{p['port']}\n")

    with open(f"{OUTPUT_DIR}/socks5_proxies.txt", "w") as f:
        for p in valid_socks5:
            f.write(f"{p['ip']}:{p['port']}\n")

    # 同时写一份JSON供调试
    with open(f"{OUTPUT_DIR}/proxies.json", "w") as f:
        json.dump({"http": valid_http, "socks5": valid_socks5}, f, indent=2)

    print("代理列表已保存到 docs/ 目录")


if __name__ == "__main__":
    asyncio.run(main())
