# Auto PAC Proxy

由 GitHub Actions 驱动的全自动在线 PAC 代理文件生成器。

## 功能

- **定时抓取**：北京时间每天 7:00 / 10:00 / 13:00 / 16:00 / 19:00 自动运行
- **多源聚合**：ProxyScrape、Databay、GitHub 公开代理池
- **实时验证**：并发 TCP + HTTP 探测，筛选低延迟可用节点
- **智能 PAC**：国内域名直连，海外流量自动走 HTTP → SOCKS5 → DIRECT fallback
- **零本地代理**：PAC 内所有代理地址均为公网 IP，**不指向 127.0.0.1**
- **Pages 托管**：自动部署到 GitHub Pages，浏览器直接订阅在线地址

## 仓库结构

```
.
├── .github/workflows/proxy-pac.yml   # 工作流：定时触发 + Pages 部署
├── scripts/
│   ├── fetch_proxies.py              # 抓取 & 验证代理
│   └── generate_pac.py               # 生成 PAC 文件
├── docs/
│   ├── index.html                    # Pages 入口（可查看状态）
│   ├── proxy.pac                     # 生成的 PAC 文件（自动部署）
│   ├── proxies.json                  # 原始代理数据
│   ├── http_proxies.txt              # HTTP 代理列表
│   └── socks5_proxies.txt            # SOCKS5 代理列表
└── README.md
```

## 快速开始

### 1. 创建仓库并上传文件

将本仓库所有文件推送到你的 GitHub 仓库（公开仓库即可，私有仓库 Pages 也可工作）。

### 2. 开启 GitHub Pages

进入仓库 **Settings → Pages**：
- **Source**: GitHub Actions
- 或选择 **Deploy from a branch** → `gh-pages` / `main` 的 `docs/` 文件夹

> 本工作流使用 `actions/deploy-pages` 自动部署，无需手动配置分支。

### 3. 获取 PAC 地址

首次运行工作流（或手动触发 `workflow_dispatch`）后，访问：

```
https://<你的用户名>.github.io/<仓库名>/proxy.pac
```

例如：`https://luckyprc.github.io/auto-pac-proxy/proxy.pac`

### 4. 浏览器配置

| 工具 | 设置位置 |
|------|---------|
| Chrome + SwitchProxy / SwitchyOmega | 扩展选项 → 自动切换 → PAC 地址 |
| Firefox | 设置 → 网络设置 → 自动代理配置 URL |
| Windows 系统代理 | 设置 → 网络和 Internet → 代理 → 使用设置脚本 |
| macOS | 系统设置 → 网络 → 详细信息 → 代理 → 自动代理配置 |

## 工作流 Cron 说明

GitHub Actions 在 2026 年 3 月更新后支持 `timezone` 字段，因此可直接使用北京时间：

```yaml
on:
  schedule:
    - cron: "0 7,10,13,16,19 * * *"
      timezone: "Asia/Shanghai"
```

对应 UTC 时间为 23:00(前一日)、2:00、5:00、8:00、11:00。

## 自定义

### 增加代理源

编辑 `scripts/fetch_proxies.py` 中的 `SOURCES` 字典，添加新的 API 或 raw txt 地址。

### 调整验证标准

修改脚本中的：
- `TEST_TIMEOUT`：探测超时时间（默认 8 秒）
- `MAX_HTTP_PROXIES` / `MAX_SOCKS5_PROXIES`：PAC 中保留的最大代理数
- `TEST_URL`：连通性测试目标地址

### 修改 PAC 直连规则

编辑 `scripts/generate_pac.py` 中的 `DIRECT_PATTERNS` 列表，增删国内域名。

## 注意事项

1. **免费代理存活时间短**：公开代理平均存活 1~4 小时，因此每 3 小时更新一次是合理频率。
2. **安全性**：免费代理存在流量被嗅探的风险，**请勿用于登录敏感账号或传输隐私数据**。
3. **GitHub Actions 并发限制**：免费账户有并发和时长限制，本工作流单次运行约 5~10 分钟，符合要求。
4. **Pages 访问**：若在国内访问 GitHub Pages 受阻，可配合 CDN（如 jsDelivr、ghproxy）加速，但 PAC 文件本身较小，通常直接访问即可。

## License

MIT
