#!/usr/bin/env python3
"""
读取验证后的代理列表，生成在线 PAC 文件。
PAC 中不指向 127.0.0.1，全部使用真实公网代理地址。
"""
import json
import os
from datetime import datetime, timezone, timedelta

OUTPUT_DIR = "docs"
PAC_FILE = f"{OUTPUT_DIR}/proxy.pac"

# 国内/局域网直连域名列表
DIRECT_PATTERNS = [
    "*.cn", "*.com.cn", "*.gov.cn", "*.edu.cn", "*.org.cn",
    "baidu.com", "*.baidu.com", "bdstatic.com", "*.bdstatic.com",
    "taobao.com", "*.taobao.com", "tmall.com", "*.tmall.com",
    "jd.com", "*.jd.com", "qq.com", "*.qq.com", "weixin.qq.com",
    "weibo.com", "*.weibo.com", "bilibili.com", "*.bilibili.com",
    "aliyun.com", "*.aliyun.com", "alicdn.com", "*.alicdn.com",
    "wechat.com", "163.com", "*.163.com", "126.com", "*.126.com",
    "netease.com", "*.netease.com", "sina.com", "*.sina.com",
    "sinaimg.cn", "*.sinaimg.cn", "douyin.com", "*.douyin.com",
    "bytedance.net", "*.bytedance.net", "toutiao.com", "*.toutiao.com",
    "ixigua.com", "*.ixigua.com", "hicloud.com", "*.hicloud.com",
    "huawei.com", "*.huawei.com", "mi.com", "*.mi.com", "xiaomi.com", "*.xiaomi.com",
    "cnblogs.com", "*.cnblogs.com", "csdn.net", "*.csdn.net",
    "zhihu.com", "*.zhihu.com", "jianshu.com", "*.jianshu.com",
    "oschina.net", "*.oschina.net", "gitee.com", "*.gitee.com",
    "alipay.com", "*.alipay.com", "unionpay.com", "*.unionpay.com",
    "bankcomm.com", "*.bankcomm.com", "icbc.com.cn", "*.icbc.com.cn",
    "ccb.com", "*.ccb.com", "abchina.com", "*.abchina.com", "boc.cn", "*.boc.cn",
    "cmbchina.com", "*.cmbchina.com", "bankofchina.com", "*.bankofchina.com",
]


def load_proxies():
    http = []
    socks5 = []
    if os.path.exists(f"{OUTPUT_DIR}/http_proxies.txt"):
        with open(f"{OUTPUT_DIR}/http_proxies.txt") as f:
            for line in f:
                line = line.strip()
                if line:
                    http.append(line)
    if os.path.exists(f"{OUTPUT_DIR}/socks5_proxies.txt"):
        with open(f"{OUTPUT_DIR}/socks5_proxies.txt") as f:
            for line in f:
                line = line.strip()
                if line:
                    socks5.append(line)
    return http, socks5


def build_proxy_string(http_list, socks5_list):
    """
    构造 PAC 返回的代理字符串。
    格式：PROXY ip:port; SOCKS5 ip:port; DIRECT
    浏览器会按顺序尝试，失败自动fallback。
    """
    parts = []
    # 优先放入HTTP代理（最多10个）
    for addr in http_list[:10]:
        parts.append(f"PROXY {addr}")
    # 放入SOCKS5代理（最多6个）
    for addr in socks5_list[:6]:
        parts.append(f"SOCKS5 {addr}")
    # 保底直连，避免全部代理挂掉时无法上网
    parts.append("DIRECT")
    return "; ".join(parts)


def generate_pac():
    http, socks5 = load_proxies()
    if not http and not socks5:
        print("警告：没有可用代理，PAC将仅返回 DIRECT")
        proxy_string = "DIRECT"
    else:
        proxy_string = build_proxy_string(http, socks5)

    # 构建直连规则JS数组
    direct_js = ",\n        ".join(f'"{p}"' for p in DIRECT_PATTERNS)

    # 获取北京时间
    bj_time = datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8)))
    timestamp = bj_time.strftime("%Y-%m-%d %H:%M:%S")

    pac_content = f"""// PAC 文件自动生成于 {timestamp} (北京时间)
// 数据来源：公开免费代理池，经实时验证筛选
// 更新频率：每3小时（北京时间 7:00/10:00/13:00/16:00/19:00）
// 使用说明：在浏览器或 SwitchProxy 中填入本文件 Pages 地址即可

function FindProxyForURL(url, host) {{
    // 1. 局域网/本地地址直连
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") ||
        isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.255.255.0")) {{
        return "DIRECT";
    }}

    // 2. 国内常用域名直连（提升访问速度）
    var directHosts = [
        {direct_js}
    ];

    for (var i = 0; i < directHosts.length; i++) {{
        if (shExpMatch(host, directHosts[i])) {{
            return "DIRECT";
        }}
    }}

    // 3. 其他流量走代理池（HTTP → SOCKS5 → DIRECT fallback）
    return "{proxy_string}";
}}
"""

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(PAC_FILE, "w", encoding="utf-8") as f:
        f.write(pac_content)

    print(f"PAC 文件已生成: {PAC_FILE}")
    print(f"  HTTP代理数: {len(http)}")
    print(f"  SOCKS5代理数: {len(socks5)}")
    print(f"  代理链长度: {proxy_string.count(';') + 1}")


if __name__ == "__main__":
    generate_pac()
