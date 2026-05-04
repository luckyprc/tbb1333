#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
节点聚合器（极速保底版）
- TCP 超时 3 秒（连不上就扔，不等）
- DNS 解析 3 秒超时（防卡死）
- IP 查询 8 线程 + 0.5 秒间隔（防串行阻塞）
- 地域过滤失败时输出 TCP 通过节点保底（不空跑）
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

TCP_LATENCY_THRESHOLD = 599
HTTP_LATENCY_THRESHOLD = 599
HTTP_CHECK_URL = "http://connectivitycheck.platform.hicloud.com/generate_204"
TCP_TIMEOUT = 3          # 连不上就快速放弃，不傻等
DNS_TIMEOUT = 3          # DNS 解析超时
MAX_WORKERS = 64
IP_QUERY_WORKERS = 8     # 降低并发，减少限流触发
IP_QUERY_DELAY = 0.5     # 缩短间隔

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
    '.ki', '.tv', '.to', '.ws',
