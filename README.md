# Nodes

ProxyScrape 注册与代理导出工具。Turnstile token 可通过 2Captcha API 或本地浏览器获取，邮箱创建、注册、收信、验证、免费 Premium DC trial 领取与代理列表获取均通过 HTTP 完成。

项目同时提供受登录保护的 Web 控制台，可在浏览器中启动单个/批量任务、
查看实时进度、账号状态、任务日志并下载账号或代理文件。
可与这个项目做代理池 导入使用
https://github.com/Resinat/Resin

## 运行界面

![命令行运行界面](docs/images/runtime-menu.png)

启动后可设置注册数量、并发线程数以及是否隐藏浏览器窗口。

## 免责声明

本项目仅供技术研究、学习交流及合法授权的自动化测试使用，不得用于违反所在地法律法规、目标平台服务条款或损害第三方权益的活动。严禁用于批量养号、垃圾信息、欺诈、绕过访问控制或风控机制等滥用场景。

使用者应自行确认其操作已获得必要授权，并独立承担账号封禁、数据丢失、服务中断及其他直接或间接后果。项目作者与贡献者不对软件的可用性、准确性、合规性作任何明示或默示保证，也不对使用本项目产生的损失或法律责任负责。

## 项目文件

| 文件 | 说明 |
|------|------|
| `proxyscrape_register.py` | 交互式注册、邮箱验证与代理导出入口 |
| `web_app.py` | 经过登录、CSRF 和限速保护的 Web API |
| `templates/`, `static/` | 响应式仪表盘前端 |
| `proxyscrape_auth.py` | ProxyScrape 登录、注册与 Token 管理封装 |
| `启动注册.bat` | Windows 启动脚本 |
| `account/` | 本地账号与 Token 输出，不进入 Git |
| `node/` | 本地代理账号和节点输出，不进入 Git |

## 环境要求

- Python 3.10+
- Chromium/Chrome
- `turnstilePatch` 浏览器扩展（已随仓库提供，见项目内 `turnstilePatch/`，开箱即用）

安装 Python 依赖：

```bash
python -m pip install -r requirements.txt
```

## 本地隐私配置

项目不会在源码中保存邮箱 API Key、自有域名或本机绝对路径。支持自建云芯邮箱 API 和原有 YYDS Mail。

**方式一：配置文件（推荐，最省事）**

复制模板并填入你自己的 Key：

```bash
cp config.local.json.example config.local.json
```

然后编辑 `config.local.json`。自建云芯邮箱示例：

```json
{
  "mail_provider": "yunxin",
  "mail_api_base": "https://YOUR_DOMAIN.example",
  "mail_api_key": "qm_你的密钥",
  "mail_type": "mail",
  "mail_suffix": "mail.com",
  "mail_domain": "",
  "captcha_provider": "2captcha",
  "captcha_api_key": "你的 2Captcha API Key",
  "captcha_api_base": "https://api.2captcha.com",
  "captcha_timeout": 180,
  "captcha_poll_interval": 5,
  "turnstile_extension_path": ""
}
```

配置字段：

| 字段 | 必需 | 说明 |
|------|------|------|
| `mail_provider` | 是 | `yunxin` 使用自建 HTTPS API；`yyds` 使用原接口 |
| `mail_api_base` | yunxin 必需 | 云芯邮箱服务地址 |
| `mail_api_key` | yunxin 必需 | `qm_` 开头的 API 密钥 |
| `mail_type` | 否 | `mail`、`cf` 或 `auto`；默认 `mail` |
| `mail_suffix` | 否 | `mail` 类型的后缀，例如 `mail.com` |
| `mail_domain` | 否 | 仅用于 `cf` 自有域名，不要填写 mail.com 后缀 |
| `yyds_api_key` | yyds 必需 | YYDS Mail API Key |
| `yyds_domain` | 否 | 已在 YYDS 验证的自有域名 |
| `captcha_provider` | 否 | `2captcha` 使用远程打码；`browser` 保留原浏览器扩展方案 |
| `captcha_api_key` | 2captcha 必需 | 2Captcha API Key，只保存在本地配置中 |
| `captcha_api_base` | 否 | 默认 `https://api.2captcha.com` |
| `captcha_timeout` | 否 | 单个 Turnstile 任务超时秒数，默认 180 |
| `captcha_poll_interval` | 否 | 查询结果间隔秒数，最小 5 秒 |
| `turnstile_extension_path` | 否 | 留空即用仓库自带的 `turnstilePatch/`；仅当想换成本机其它目录时才填 |

`config.local.json` 已被 `.gitignore` 排除，不会进入仓库。

**方式二：环境变量（会覆盖配置文件同名项）**

| 环境变量 | 必需 | 说明 |
|----------|------|------|
| `MAIL_PROVIDER` | 否 | `yunxin` 或 `yyds` |
| `MAIL_API_BASE` | yunxin 必需 | 云芯邮箱服务地址 |
| `MAIL_API_KEY` | yunxin 必需 | `qm_` 开头的 API 密钥 |
| `MAIL_TYPE` | 否 | `mail`、`cf` 或 `auto` |
| `MAIL_SUFFIX` | 否 | mail.com 母号别名后缀 |
| `MAIL_DOMAIN` | 否 | CF 自有域名 |
| `YYDS_API_KEY` | 是 | YYDS Mail API Key |
| `YYDS_DOMAIN` | 否 | 已验证的自有域名；留空则由 YYDS 选择 |
| `CAPTCHA_PROVIDER` | 否 | `2captcha` 或 `browser` |
| `CAPTCHA_API_KEY` | 2captcha 必需 | 2Captcha API Key |
| `CAPTCHA_API_BASE` | 否 | 2Captcha API 根地址 |
| `CAPTCHA_TIMEOUT` | 否 | 单任务超时秒数 |
| `CAPTCHA_POLL_INTERVAL` | 否 | 查询结果间隔秒数，最小 5 秒 |
| `TURNSTILE_EXTENSION_PATH` | 否 | 留空即用仓库自带扩展；仅覆盖为本机其它目录时才填 |
| `PYTHON_EXE` | 否 | `启动注册.bat` 使用的 Python；默认使用 PATH 中的 `python` |

PowerShell 当前窗口配置示例：

```powershell
$env:MAIL_PROVIDER = "yunxin"
$env:MAIL_API_BASE = "https://YOUR_DOMAIN.example"
$env:MAIL_API_KEY = "YOUR_SECRET_HERE"
$env:MAIL_TYPE = "mail"
$env:MAIL_SUFFIX = "mail.com"
python .\proxyscrape_register.py
```

这些值只存在于当前 PowerShell 进程，不会写入仓库。

## 切换邮箱服务

使用原有 YYDS 时设置：

```json
{
  "mail_provider": "yyds",
  "yyds_api_key": "你的 YYDS API Key",
  "yyds_domain": ""
}
```

### 云芯 mail.com 后缀

使用 `/api/v1/suffixes` 返回的后缀：

```powershell
$env:MAIL_TYPE = "mail"
$env:MAIL_SUFFIX = "mail.com"
Remove-Item Env:MAIL_DOMAIN -ErrorAction SilentlyContinue
```

### 云芯 CF 自有域名

`mail_domain` 只用于 `/api/config` 返回的 CF 域名：

```powershell
$env:MAIL_TYPE = "cf"
$env:MAIL_SUFFIX = ""
$env:MAIL_DOMAIN = "mail.example.com"
```

`mail.example.com` 是占位符，需替换为云芯 `/api/config` 中实际启用的域名。切换配置后重新启动程序。

## 运行

PowerShell：

```powershell
python .\proxyscrape_register.py
```

或双击 `启动注册.bat`。如果 Python 不在 PATH 中，可先设置：

```powershell
$env:PYTHON_EXE = "D:\path\to\python.exe"
```

运行结果会写入：

- `account/accounts_*.jsonl`：邮箱、密码、访问 Token 和账户信息。
- `node/proxies_*.txt`：代理用户名、密码和节点地址。
- `proxyscrape_token.json`：`proxyscrape_auth.py` 的本地登录会话。

以上均包含敏感信息，已由 `.gitignore` 排除，禁止手动强制提交。

## 安全检查

上传或分享前建议执行：

```bash
git status --ignored
git grep -n -I -E "API_KEY|access_token|refresh_token|proxy_password"
```

公开的 ProxyScrape Turnstile sitekey 和 Google OAuth Client ID 来自网页前端，不是账户私钥；邮箱 API Key、登录 Token、邮箱账户和代理凭据必须始终保留在本地。
