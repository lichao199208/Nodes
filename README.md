# Nodes

Nodes 是一个面向 ProxyScrape 账户注册、邮箱验证、试用代理领取、代理质量检测和订阅导出的自动化管理项目。项目同时提供命令行入口和中文 Web 控制台，可集中管理任务、账号、代理库存、质量策略、审计记录及下游订阅。

> **使用前请确认授权。** 本项目仅用于技术研究、学习交流和合法授权的自动化测试。请遵守目标平台服务条款及所在地法律法规，不得用于批量滥用、垃圾信息、欺诈、规避访问控制或其他损害第三方权益的行为。

## 功能概览

- 中文响应式 Web 控制台，兼容桌面和手机浏览器。
- 单个或批量注册任务、实时进度、日志和历史记录。
- 支持自建云芯邮箱 API，并保留 YYDS Mail 兼容配置。
- 支持 2Captcha API，也可切换本地 Chromium 浏览器流程。
- 账户导入、刷新、删除、用量同步和 API Key 管理。
- 代理库存、延迟、出口 IP、地区及健康状态管理。
- 按延迟、地区、连通性和探测条件执行质量筛选。
- 根据账户槽位和库存容量自动补充注册任务。
- 导出实时代理、合格代理、GPT 网关、Clash YAML 和阶梯代理。
- 可接入 [Resin](https://github.com/Resinat/Resin) 统一管理和调度。
- 登录保护、CSRF、登录限速、安全 Cookie、字段脱敏和审计记录。

在线入口：<https://zf.qkmss.com/nodes/>（是否开放及登录方式由部署者决定）。

## 项目结构

| 路径 | 用途 |
|---|---|
| `proxyscrape_register.py` | 注册、邮箱验证、试用领取和代理导出的主流程 |
| `proxyscrape_auth.py` | ProxyScrape 登录、注册及 Token 管理 |
| `web_app.py` / `wsgi.py` | Web 控制台、JSON API 和 WSGI 入口 |
| `pool.py` | 账户与代理池容量管理 |
| `proxy_quality.py` | 代理检测、质量规则和筛选逻辑 |
| `platform_store.py` | 平台配置与持久化 |
| `filter_xai_proxies.py` | 代理可用性批量检测工具 |
| `templates/`、`static/` | 中文响应式 Web 前端 |
| `turnstilePatch/` | 浏览器模式使用的扩展资源 |
| `compose.yml`、`Dockerfile` | Docker 构建与部署配置 |
| `DEPLOYMENT.md` | 服务器部署与维护补充说明 |

运行数据默认写入 `account/`、`node/` 和 Web 数据目录。它们可能包含账户、Token 或代理凭据，不应提交到 Git。

## Docker 快速开始

要求：Docker、Docker Compose v2。

```bash
git clone https://github.com/lichao199208/Nodes.git
cd Nodes
cp config.local.json.example config.local.json
chmod 600 config.local.json
```

生成 Web 密码哈希和会话密钥：

```bash
python - <<'PY'
import secrets
from werkzeug.security import generate_password_hash
print("web_password_hash:", generate_password_hash("请替换为强密码"))
print("web_session_secret:", secrets.token_hex(32))
PY
```

编辑 `config.local.json` 后构建并启动：

```bash
docker compose build
docker compose up -d dashboard dashboard-proxy
docker compose ps
docker compose logs -f dashboard
```

示例 Compose 通过 `https://服务器地址:8443/` 暴露控制台。部署前需在 `certs/` 放置 `fullchain.pem` 和 `privkey.pem`，也可以修改配置接入已有 Nginx/Caddy。

## Python 本地运行

要求：Python 3.10+、Chrome/Chromium。

```bash
python -m venv .venv
source .venv/bin/activate
# Windows PowerShell: ..venvScriptsActivate.ps1
python -m pip install -r requirements.txt
cp config.local.json.example config.local.json
python proxyscrape_register.py
```

Windows 也可运行 `start.bat`。生产环境启动 Web 控制台：

```bash
gunicorn --bind 127.0.0.1:8080 --workers 1 --threads 8 --timeout 900 wsgi:app
```

生产环境建议由 Nginx/Caddy 终止 TLS。

## 配置说明

配置读取自 `config.local.json`，环境变量可覆盖对应设置。完整字段见 [config.local.json.example](config.local.json.example)。

### 邮箱服务

```json
{
  "mail_provider": "yunxin",
  "mail_api_base": "https://mail.example.com",
  "mail_api_key": "YOUR_MAIL_API_KEY",
  "mail_type": "mail",
  "mail_suffix": "mail.com",
  "mail_domain": ""
}
```

YYDS Mail 兼容字段为 `yyds_api_key` 和 `yyds_domain`。请勿将真实 Key、域名或邮箱账户提交到仓库。

### 验证码服务

```json
{
  "captcha_provider": "2captcha",
  "captcha_api_key": "YOUR_2CAPTCHA_API_KEY",
  "captcha_api_base": "https://api.2captcha.com",
  "captcha_timeout": 180,
  "captcha_poll_interval": 5
}
```

如需使用本地浏览器流程，将 `captcha_provider` 设置为 `browser`，并按需设置 `turnstile_extension_path`。验证码是否通过由目标站点决定，项目不会把未完成验证的任务标记为成功。

### Web 登录与导出

| 字段 | 说明 |
|---|---|
| `web_username` | 控制台用户名 |
| `web_password_hash` | Werkzeug 生成的密码哈希，不保存明文密码 |
| `web_session_secret` | 至少 32 字节的随机会话密钥 |
| `export_token` | 保护订阅导出接口的随机令牌 |

生产环境必须使用 HTTPS，并限制配置文件、数据目录和备份文件权限。

### 代理质量策略

| 字段 | 用途 |
|---|---|
| `http_proxy` / `https_proxy` | 注册与 API 请求使用的上游代理 |
| `proxy_quality_enabled` | 是否启用质量筛选 |
| `proxy_max_latency_ms` | 最大允许延迟 |
| `proxy_exclude_countries` | 排除的国家/地区代码 |
| `proxy_arp_check_enabled` | 是否执行指定目标探测 |
| `proxy_quality_workers` | 并行检测数 |
| `proxy_quality_cache_ttl_sec` | 检测结果缓存时间 |

## 使用 Web 控制台

登录后可以：

1. 查看账户、代理、任务和容量摘要。
2. 创建注册任务并观察阶段进度与日志。
3. 查看账户验证状态、配额、API Key 状态并同步使用量。
4. 查看代理质量、地区、出口 IP 和库存历史快照。
5. 调整邮箱、代理池、质量策略和导出配置。
6. 在审计页面检查管理操作。

控制台对状态变更请求启用 CSRF 校验；直接调用管理 API 时必须先完成登录并携带有效会话与 CSRF Token。

## 导出代理和订阅

| 接口 | 用途 |
|---|---|
| `/api/health` | 服务健康检查 |
| `/api/export/live-proxies` | 导出实时代理列表 |
| `/api/export/qualified-proxies` | 导出通过质量规则的代理 |
| `/api/export/gpt-gateway` | 导出网关格式 |
| `/api/export/clash.yml/<EXPORT_TOKEN>` | Clash YAML 订阅 |
| `/api/export/ladder` | 阶梯代理导出 |

将 Clash 订阅接入 Resin：

```text
https://YOUR_NODES_HOST/api/export/clash.yml/YOUR_EXPORT_TOKEN
```

在 Resin 的“订阅”页面新建远程订阅并填写该 URL。请把导出令牌视为密码，不要公开分享。

## 测试

```bash
python -m pytest -q
python -m py_compile web_app.py proxyscrape_register.py proxyscrape_auth.py
git diff --check
```

## 常见问题

### 浏览器找不到

确认 Chrome/Chromium 已安装，并通过环境变量或配置指定可执行文件路径。Linux 容器还需要足够的 `/dev/shm`，Compose 已示例配置 `shm_size: 2gb`。

### 注册页能打开但验证超时

依次检查服务器时间、DNS、上游代理、浏览器版本、目标站点可达性以及验证码服务余额/响应。不要高频循环重试，目标站点可能对数据中心 IP 或异常请求触发风控。

### 任务完成但没有代理

完成邮箱验证不一定代表能够领取试用代理。检查账户试用资格、是否已领取过试用、任务日志中的 API 响应，以及质量策略是否过滤了全部代理。

### 下游订阅为空

确认已有有效库存、导出令牌正确、质量规则没有排除全部节点，并从服务器本机请求导出 URL 检查状态和响应内容。

## 数据与安全

- `config.local.json`、账户文件、代理文件、Token、日志和备份可能包含敏感信息。
- 不要提交真实 API Key、Cookie、会话密钥、服务器密码、代理凭据或生产私有信息。
- 建议配置和凭据文件使用 `0600` 权限，数据目录使用 `0700` 权限。
- 对外部署时使用 HTTPS、强密码、随机导出令牌，并通过防火墙限制管理入口。
- 定期轮换邮箱 API Key、验证码服务 Key、Web 会话密钥和导出令牌。

提交前人工复核敏感字段：

```bash
git status --ignored
git grep -n -I -E "(api[_-]?key|access[_-]?token|refresh[_-]?token|password|proxy[_-]?pass)"
```

## 更新部署

```bash
cp config.local.json config.local.json.backup
docker compose down
git pull --ff-only
docker compose build --pull
docker compose up -d dashboard dashboard-proxy
```

更多服务器说明见 [DEPLOYMENT.md](DEPLOYMENT.md)。

## 免责声明

本软件按“现状”提供，不对可用性、准确性、持续兼容性或特定用途作保证。使用者应自行确认操作授权、数据来源和合规要求，并独立承担账号封禁、费用、数据丢失、服务中断及其他直接或间接后果。项目作者和贡献者不对使用本项目产生的损失或法律责任负责。

## 致谢

- 上游项目：[kingenbomb/Nodes](https://github.com/kingenbomb/Nodes)
- 代理池网关：[Resinat/Resin](https://github.com/Resinat/Resin)

欢迎通过 Issue 提交可复现问题；请在提交日志前删除邮箱、Token、API Key、代理凭据和服务器信息。
