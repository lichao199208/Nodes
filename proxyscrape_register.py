# -*- coding: utf-8 -*-
"""
ProxyScrape 自动注册 —— 本地打码走协议

思路（最快最省）：
  · 浏览器（DrissionPage + turnstilePatch 扩展）只干一件事：在真实 sign-up 页
    里让 Cloudflare Turnstile 自动过，读出隐藏字段 cf-turnstile-response 的 token。
    token 在真实域名 dashboard.proxyscrape.com 下生成，hostname 天然匹配，
    服务端 siteverify 不会因 hostname 拒绝。
  · 临时邮箱、注册、收验证码、验邮箱 —— 全部走 HTTP 协议，不碰浏览器。

依赖：DrissionPage / requests（用 grok 项目那个 venv 跑即可）
用法：python proxyscrape_register.py
"""

import os
import re
import sys
import time
import json
import random
import string
import threading
import html as _html
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

_BASE = os.path.dirname(os.path.abspath(__file__))
_LOCAL_CONFIG_FILE = os.environ.get("NODES_CONFIG_FILE") or os.path.join(_BASE, "config.local.json")


def _load_local_config():
    if not os.path.exists(_LOCAL_CONFIG_FILE):
        return {}
    try:
        with open(_LOCAL_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[!] 读取本地配置失败: {e}")
        return {}


_LOCAL_CONFIG = _load_local_config()


def _setting(config_name, env_name, default=""):
    """Environment variables override config.local.json when both are present."""
    return os.environ.get(env_name) or _LOCAL_CONFIG.get(config_name) or default


# ── 配置 ────────────────────────────────────────────────
# 邮箱服务：默认兼容原有 YYDS，也支持自建云芯邮箱 API。
MAIL_PROVIDER = str(_setting("mail_provider", "MAIL_PROVIDER")).strip().lower()
MAIL_API_BASE = str(_setting(
    "mail_api_base", "MAIL_API_BASE", "https://mail.example.com"
)).strip().rstrip("/")
MAIL_API_KEY = str(_setting("mail_api_key", "MAIL_API_KEY")).strip()
MAIL_TYPE = str(_setting("mail_type", "MAIL_TYPE", "mail")).strip().lower()
MAIL_SUFFIX = str(_setting("mail_suffix", "MAIL_SUFFIX", "mail.com")).strip()
MAIL_DOMAIN = str(_setting("mail_domain", "MAIL_DOMAIN")).strip()

# YYDS Mail（向后兼容）
YYDS_BASE = "https://maliapi.215.im/v1"
YYDS_KEY = str(_setting("yyds_api_key", "YYDS_API_KEY")).strip()
YYDS_DOMAIN = str(_setting("yyds_domain", "YYDS_DOMAIN")).strip()

# Turnstile solver. When a 2Captcha key is configured, use its API by default;
# otherwise keep the original browser solver for backward compatibility.
CAPTCHA_API_KEY = str(_setting("captcha_api_key", "CAPTCHA_API_KEY")).strip()
CAPTCHA_PROVIDER = str(_setting(
    "captcha_provider", "CAPTCHA_PROVIDER",
    "2captcha" if CAPTCHA_API_KEY else "browser",
)).strip().lower()
CAPTCHA_API_BASE = str(_setting(
    "captcha_api_base", "CAPTCHA_API_BASE", "https://api.2captcha.com",
)).strip().rstrip("/")
CAPTCHA_TIMEOUT = int(_setting("captcha_timeout", "CAPTCHA_TIMEOUT", 180))
CAPTCHA_POLL_INTERVAL = max(
    5.0, float(_setting("captcha_poll_interval", "CAPTCHA_POLL_INTERVAL", 5))
)

if not MAIL_PROVIDER:
    MAIL_PROVIDER = "yunxin" if MAIL_API_KEY else "yyds"

# ProxyScrape dashboard
PS_BASE = "https://dashboard.proxyscrape.com"
PS_REGISTER = f"{PS_BASE}/v2/v4/account/auth/register"
PS_LOGIN = f"{PS_BASE}/v2/v4/account/auth/login"
PS_ME = f"{PS_BASE}/v2/v4/account/auth/me"
PS_VERIFY_EMAIL = f"{PS_BASE}/v2/v4/account/verify-email"
PS_RESEND = f"{PS_BASE}/v2/v4/account/reset-verification-code"
PS_TRIAL_ELIGIBILITY = f"{PS_BASE}/v2/v4/account/premium/trial-eligibility"
PS_CLAIM_TRIAL = f"{PS_BASE}/v2/v4/account/premium/claim-trial"
PS_SIGNUP_PAGE = f"{PS_BASE}/v2/sign-up"
PS_SITEKEY = "0x4AAAAAAAFWUVCKyusT9T8r"
PS_API_KEYS = f"{PS_BASE}/v2/v4/account/api-keys"
PS_PERM_CTX = f"{PS_BASE}/v2/v4/account/api-keys/permission-context"
PS_ACCOUNTS_SUMMARY = f"{PS_BASE}/v2/v4/account/accounts-summary"
PS_PUBLIC_API = "https://api.proxyscrape.com"
API_KEY_NAME = "nodes"

DEFAULT_API_PERMISSIONS = [
    "subaccount:read", "subaccount:write", "subaccount:delete",
    "account:apikeys:create", "account:apikeys:read", "account:apikeys:update",
    "account:apikeys:delete", "account:apikeys:regenerate",
    "residential_unlimited:read", "residential_unlimited:write", "residential_unlimited:delete",
    "serp_api:read", "serp_api:write", "serp_api:delete",
    "datacenter_shared:read", "datacenter_shared:write", "datacenter_shared:delete",
    "datacenter_dedicated:read", "datacenter_dedicated:write", "datacenter_dedicated:delete",
    "residential:read", "residential:write", "residential:delete",
]

PERMISSION_CATALOG = {
    "allowed_permissions": list(DEFAULT_API_PERMISSIONS),
    "structure": {
        "account": {"sub_types": [
            {"name": "Subaccount", "description": "子账号只读/读写/删除", "permissions": [
                {"id": "subaccount:read", "name": "Read", "description": "查看子账号统计和设置"},
                {"id": "subaccount:write", "name": "Write", "description": "管理并更新子账号"},
                {"id": "subaccount:delete", "name": "Delete", "description": "删除子账号/子用户"},
            ]},
            {"name": "API Key Management", "description": "创建、查看、更新、吊销 API 密钥", "permissions": [
                {"id": "account:apikeys:create", "name": "Create", "description": "创建新 API 密钥"},
                {"id": "account:apikeys:read", "name": "Read", "description": "查看 API 密钥及设置"},
                {"id": "account:apikeys:update", "name": "Update", "description": "修改已有 API 密钥"},
                {"id": "account:apikeys:delete", "name": "Delete", "description": "删除/吊销 API 密钥"},
                {"id": "account:apikeys:regenerate", "name": "Regenerate", "description": "重新生成 API 密钥"},
            ]},
        ]},
        "product": {"sub_types": [
            {"name": "Residential Unlimited", "description": "无限住宅代理", "permissions": [
                {"id": "residential_unlimited:read", "name": "Read", "description": "查看无限住宅统计和设置"},
                {"id": "residential_unlimited:write", "name": "Write", "description": "管理并更新无限住宅"},
                {"id": "residential_unlimited:delete", "name": "Delete", "description": "删除无限住宅子账号/子用户"},
            ]},
            {"name": "SERP API", "description": "SERP API", "permissions": [
                {"id": "serp_api:read", "name": "Read", "description": "查看 SERP API 统计和设置"},
                {"id": "serp_api:write", "name": "Write", "description": "管理并更新 SERP API"},
                {"id": "serp_api:delete", "name": "Delete", "description": "删除 SERP API 子账号/子用户"},
            ]},
            {"name": "Datacenter Shared (Premium)", "description": "共享数据中心 Premium", "permissions": [
                {"id": "datacenter_shared:read", "name": "Read", "description": "查看共享数据中心统计和设置"},
                {"id": "datacenter_shared:write", "name": "Write", "description": "管理并更新共享数据中心"},
                {"id": "datacenter_shared:delete", "name": "Delete", "description": "删除共享数据中心子账号/子用户"},
            ]},
            {"name": "Datacenter Dedicated", "description": "独立数据中心", "permissions": [
                {"id": "datacenter_dedicated:read", "name": "Read", "description": "查看独立数据中心统计和设置"},
                {"id": "datacenter_dedicated:write", "name": "Write", "description": "管理并更新独立数据中心"},
                {"id": "datacenter_dedicated:delete", "name": "Delete", "description": "删除独立数据中心子账号/子用户"},
            ]},
            {"name": "Residential", "description": "住宅代理", "permissions": [
                {"id": "residential:read", "name": "Read", "description": "查看住宅代理统计和设置"},
                {"id": "residential:write", "name": "Write", "description": "管理并更新住宅代理"},
                {"id": "residential:delete", "name": "Delete", "description": "删除住宅代理子账号/子用户"},
            ]},
        ]},
    },
}

# turnstilePatch 扩展：默认读取项目内目录，也可通过环境变量覆盖
EXTENSION_PATH = str(
    _LOCAL_CONFIG.get("turnstile_extension_path")
    or os.environ.get("TURNSTILE_EXTENSION_PATH")
    or os.path.join(_BASE, "turnstilePatch")
).strip()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36")

# 输出目录：账号 → account/  代理节点 → node/
_ACCOUNT_DIR = os.path.join(_BASE, "account")
_NODE_DIR = os.path.join(_BASE, "node")


def _apply_proxy_env():
    enabled = str(_LOCAL_CONFIG.get("proxy_enabled") or "").strip().lower() in {"1", "true", "yes", "on"}
    http_proxy = str(_LOCAL_CONFIG.get("http_proxy") or "").strip()
    https_proxy = str(_LOCAL_CONFIG.get("https_proxy") or "").strip() or http_proxy
    no_proxy = str(_LOCAL_CONFIG.get("no_proxy") or "localhost,127.0.0.1").strip()
    if enabled and (http_proxy or https_proxy):
        if http_proxy:
            os.environ["HTTP_PROXY"] = http_proxy
            os.environ["http_proxy"] = http_proxy
        if https_proxy:
            os.environ["HTTPS_PROXY"] = https_proxy
            os.environ["https_proxy"] = https_proxy
        os.environ["NO_PROXY"] = no_proxy
        os.environ["no_proxy"] = no_proxy
        return
    for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        os.environ.pop(key, None)


def reload_settings():
    """Re-read config.local.json into module globals after the dashboard saves."""
    global _LOCAL_CONFIG, MAIL_PROVIDER, MAIL_API_BASE, MAIL_API_KEY, MAIL_TYPE
    global MAIL_SUFFIX, MAIL_DOMAIN, YYDS_KEY, YYDS_DOMAIN, CAPTCHA_API_KEY
    global CAPTCHA_PROVIDER, CAPTCHA_API_BASE, CAPTCHA_TIMEOUT, CAPTCHA_POLL_INTERVAL
    global EXTENSION_PATH
    _LOCAL_CONFIG = _load_local_config()
    MAIL_PROVIDER = str(_setting("mail_provider", "MAIL_PROVIDER")).strip().lower()
    MAIL_API_BASE = str(_setting(
        "mail_api_base", "MAIL_API_BASE", "https://mail.example.com"
    )).strip().rstrip("/")
    MAIL_API_KEY = str(_setting("mail_api_key", "MAIL_API_KEY")).strip()
    MAIL_TYPE = str(_setting("mail_type", "MAIL_TYPE", "mail")).strip().lower()
    MAIL_SUFFIX = str(_setting("mail_suffix", "MAIL_SUFFIX", "mail.com")).strip()
    MAIL_DOMAIN = str(_setting("mail_domain", "MAIL_DOMAIN")).strip()
    YYDS_KEY = str(_setting("yyds_api_key", "YYDS_API_KEY")).strip()
    YYDS_DOMAIN = str(_setting("yyds_domain", "YYDS_DOMAIN")).strip()
    CAPTCHA_API_KEY = str(_setting("captcha_api_key", "CAPTCHA_API_KEY")).strip()
    CAPTCHA_PROVIDER = str(_setting(
        "captcha_provider", "CAPTCHA_PROVIDER",
        "2captcha" if CAPTCHA_API_KEY else "browser",
    )).strip().lower()
    CAPTCHA_API_BASE = str(_setting(
        "captcha_api_base", "CAPTCHA_API_BASE", "https://api.2captcha.com",
    )).strip().rstrip("/")
    CAPTCHA_TIMEOUT = int(_setting("captcha_timeout", "CAPTCHA_TIMEOUT", 180))
    CAPTCHA_POLL_INTERVAL = max(
        5.0, float(_setting("captcha_poll_interval", "CAPTCHA_POLL_INTERVAL", 5))
    )
    if not MAIL_PROVIDER:
        MAIL_PROVIDER = "yunxin" if MAIL_API_KEY else "yyds"
    EXTENSION_PATH = str(
        _LOCAL_CONFIG.get("turnstile_extension_path")
        or os.environ.get("TURNSTILE_EXTENSION_PATH")
        or os.path.join(_BASE, "turnstilePatch")
    ).strip()
    _apply_proxy_env()


_apply_proxy_env()
os.makedirs(_ACCOUNT_DIR, exist_ok=True)
os.makedirs(_NODE_DIR, exist_ok=True)

HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "User-Agent": UA,
    "Origin": PS_BASE,
    "Referer": PS_SIGNUP_PAGE,
}


_print_lock = threading.Lock()
_file_lock = threading.Lock()
_tls = threading.local()


def log(msg):
    tag = getattr(_tls, "tag", "")
    with _print_lock:
        print(f"[{time.strftime('%H:%M:%S')}]{tag} {msg}", flush=True)


def _retry(fn, tries=3, delay=2.0, what=""):
    """通用重试：捕获异常，退避后重试；用尽则抛最后一次异常。"""
    last = None
    for i in range(1, tries + 1):
        try:
            return fn()
        except Exception as e:
            last = e
            if i < tries:
                log(f"[retry {i}/{tries}] {what or 'op'} 失败: {str(e)[:100]}，{delay:.0f}s 后重试")
                time.sleep(delay)
    raise last


_CONSONANTS = "bcdfghjklmnpqrstvwxz"
_VOWELS = "aeiou"


def _syllable():
    ending = _CONSONANTS + _VOWELS
    return random.choice(_CONSONANTS) + random.choice(_VOWELS) + random.choice(ending)


def random_mailbox_local():
    """Looks like a normal mailbox, not a serial batch like psxxxxxxxx."""
    style = random.randrange(4)
    if style == 0:
        local = "".join(_syllable() for _ in range(random.randint(3, 5)))
        if random.random() < 0.45:
            local += str(random.randint(11, 98))
    elif style == 1:
        length = random.randint(9, 14)
        local = random.choice(string.ascii_lowercase)
        local += "".join(random.choices(string.ascii_lowercase + string.digits, k=length - 1))
    elif style == 2:
        local = "".join(_syllable() for _ in range(4))
    else:
        local = "".join(_syllable() for _ in range(random.randint(2, 4)))
        at = random.randint(2, max(2, len(local) - 1))
        local = local[:at] + str(random.randint(2, 9)) + local[at:]
    local = re.sub(r"[^a-z0-9]", "", local.lower())
    if len(local) < 8:
        local += "".join(random.choices(string.ascii_lowercase, k=8 - len(local)))
    if local[0].isdigit():
        local = random.choice(string.ascii_lowercase) + local[1:]
    banned_prefix = ("ps", "test", "admin", "user", "mail", "temp", "tmp")
    if any(local.startswith(item) for item in banned_prefix):
        local = _syllable() + local
        local = re.sub(r"[^a-z0-9]", "", local)[:16]
        if local[0].isdigit():
            local = random.choice(string.ascii_lowercase) + local[1:]
    return local[:16]


# ── 临时邮箱（YYDS Mail 协议）────────────────────────────
def yyds_create_mailbox():
    if not YYDS_KEY:
        raise RuntimeError("未配置 YYDS_API_KEY 环境变量")

    def _do():
        local = random_mailbox_local()
        payload = {"localPart": local}
        if YYDS_DOMAIN:
            payload["domain"] = YYDS_DOMAIN
        r = requests.post(f"{YYDS_BASE}/accounts",
                          headers={"X-API-Key": YYDS_KEY, "Content-Type": "application/json"},
                          json=payload, timeout=20)
        r.raise_for_status()
        return r.json()["data"]
    d = _retry(_do, tries=3, what="建邮箱")
    log(f"临时邮箱: {d['address']}")
    return d["address"], d["token"]


def yyds_wait_code(address, timeout=180, interval=5):
    """轮询收件箱，从 HTML 正文抽取 ProxyScrape 的验证码。
    注意：码是 10 位字母数字混合（如 d253ff02f7），不是纯数字；
    且 text 版只写 'open the HTML version'，必须解析 html 字段。"""
    deadline = time.time() + timeout
    hdr = {"X-API-Key": YYDS_KEY}
    while time.time() < deadline:
        lst = requests.get(f"{YYDS_BASE}/messages", headers=hdr,
                           params={"address": address, "limit": 5}, timeout=30).json()
        for m in lst.get("data", {}).get("messages", []):
            d = requests.get(f"{YYDS_BASE}/messages/{m['id']}", headers=hdr,
                             params={"address": address}, timeout=30).json().get("data", {})
            html = " ".join(d.get("html") or [])
            txt = _html.unescape(re.sub(r"<[^>]+>", " ", html))
            mo = re.search(r"verification code:\s*([A-Za-z0-9]{6,})", txt, re.I)
            if mo:
                log(f"收到验证码: {mo.group(1)}  (主题: {d.get('subject')})")
                return mo.group(1)
        time.sleep(interval)
    raise TimeoutError("等验证码超时")


# ── 云芯邮箱 HTTPS API ──────────────────────────────────
def _yunxin_headers():
    if not MAIL_API_KEY:
        raise RuntimeError("未配置 MAIL_API_KEY")
    return {"X-API-Key": MAIL_API_KEY, "Accept": "application/json"}


def yunxin_create_mailbox():
    def _do():
        local = random_mailbox_local()
        payload = {"type": MAIL_TYPE or "mail", "prefix": local}
        if MAIL_SUFFIX and MAIL_TYPE in {"mail", "auto"}:
            payload["suffix"] = MAIL_SUFFIX
        if MAIL_DOMAIN and MAIL_TYPE in {"cf", "auto"}:
            payload["domain"] = MAIL_DOMAIN
        headers = {**_yunxin_headers(), "Content-Type": "application/json"}
        r = requests.post(f"{MAIL_API_BASE}/api/v1/mailboxes",
                          headers=headers, json=payload, timeout=30)
        r.raise_for_status()
        data = r.json()
        address = str(data.get("address") or "").strip()
        if not data.get("ok") or not address:
            raise RuntimeError(data.get("message") or "创建邮箱响应缺少 address")
        return address

    address = _retry(_do, tries=3, what="建邮箱")
    log(f"临时邮箱: {address}")
    return address, None


def _code_from_yunxin_mail(mail):
    for value in mail.get("codes") or []:
        code = str(value).strip()
        if re.fullmatch(r"[A-Za-z0-9]{6,16}", code):
            return code

    html = str(mail.get("html") or "")
    plain = " ".join(str(mail.get(key) or "") for key in ("subject", "from", "text", "content"))
    plain += " " + _html.unescape(re.sub(r"<[^>]+>", " ", html))
    for pattern in (
        r"verification\s*code(?:\s+is)?\s*[:：]?\s*([A-Za-z0-9]{6,16})",
        r"验证码(?:是|为)?\s*[:：]?\s*([A-Za-z0-9]{6,16})",
    ):
        match = re.search(pattern, plain, re.I)
        if match:
            return match.group(1)
    return ""


def yunxin_wait_code(address, timeout=180, interval=5):
    deadline = time.time() + timeout
    headers = _yunxin_headers()
    while time.time() < deadline:
        r = requests.get(f"{MAIL_API_BASE}/api/v1/mails", headers=headers,
                         params={"address": address, "limit": 20}, timeout=30)
        r.raise_for_status()
        data = r.json()
        if not data.get("ok"):
            raise RuntimeError(data.get("message") or "读取邮箱失败")
        for mail in data.get("results") or []:
            code = _code_from_yunxin_mail(mail)
            if code:
                log(f"收到验证码: {code}  (主题: {mail.get('subject')})")
                return code
        time.sleep(interval)
    raise TimeoutError("等验证码超时")


def create_mailbox():
    if MAIL_PROVIDER == "yyds":
        return yyds_create_mailbox()
    if MAIL_PROVIDER in {"yunxin", "qingyi", "custom"}:
        return yunxin_create_mailbox()
    raise RuntimeError(f"不支持的邮箱服务: {MAIL_PROVIDER}")


def wait_mail_code(address, timeout=180, interval=5):
    if MAIL_PROVIDER == "yyds":
        return yyds_wait_code(address, timeout=timeout, interval=interval)
    if MAIL_PROVIDER in {"yunxin", "qingyi", "custom"}:
        return yunxin_wait_code(address, timeout=timeout, interval=interval)
    raise RuntimeError(f"不支持的邮箱服务: {MAIL_PROVIDER}")


# ── 本地打码：浏览器只出 token ───────────────────────────
# 触发 widget 挂载：填占位表单（token 不绑定表单内容，随便填合法值即可）
_FILL_JS = r"""
function setVal(el,val){
  var setter=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set;
  setter.call(el,val);
  el.dispatchEvent(new Event('input',{bubbles:true}));
  el.dispatchEvent(new Event('change',{bubbles:true}));
}
var email=document.querySelector('input[type=email]');
var pwds=document.querySelectorAll('input[type=password]');
var chk=document.querySelector('input[type=checkbox]');
if(email) setVal(email,'warmup'+Date.now()+'@example.com');
if(pwds[0]) setVal(pwds[0],'Warmup123!9');
if(pwds[1]) setVal(pwds[1],'Warmup123!9');
if(chk&&!chk.checked) chk.click();
return 'filled';
"""

# 一次读全 widget 状态（供轮询检测用，不盲等）：页面/API/input/iframe/token
_STATE_JS = r"""
try{
  var inp=document.querySelector('input[name="cf-turnstile-response"]');
  var token=inp?String(inp.value||'').trim():'';
  if(!token && window.turnstile && typeof turnstile.getResponse==='function'){
    try{ token=String(turnstile.getResponse()||'').trim(); }catch(e){}
  }
  var ifr=document.querySelector('iframe[src*="challenges.cloudflare.com"],iframe[src*="turnstile"]');
  return JSON.stringify({
    ready: document.readyState==='complete',
    hasApi: !!(window.turnstile && typeof turnstile.render==='function'),
    hasInput: !!inp,
    hasIframe: !!ifr,
    tokenLen: token.length,
    token: token.length>=80 ? token : ''
  });
}catch(e){ return JSON.stringify({err:String(e)}); }
"""

# 注入进 turnstile iframe，伪装真实鼠标屏幕坐标（反自动化检测）
_SCREEN_INJECT_JS = r"""
window.dtp=1;
function ri(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
Object.defineProperty(MouseEvent.prototype,'screenX',{value:ri(800,1200)});
Object.defineProperty(MouseEvent.prototype,'screenY',{value:ri(400,700)});
"""

# 兜底：页面自带组件半挂载不出 iframe 时，用已知 sitekey 自己 render 一个干净 widget
_RENDER_JS = r"""
try{
  if(!window.turnstile || typeof turnstile.render!=='function') return 'no-api';
  var c=document.getElementById('__ps_ts');
  if(c && c.getAttribute('data-done')) return 'already';
  if(!c){
    c=document.createElement('div'); c.id='__ps_ts';
    c.style.cssText='position:fixed;bottom:8px;right:8px;z-index:2147483647';
    document.body.appendChild(c);
  }
  window.__ps_wid=turnstile.render(c,{
    sitekey: arguments[0],
    callback: function(t){ window.__ps_token=t; }
  });
  c.setAttribute('data-done','1');
  return 'rendered:'+window.__ps_wid;
}catch(e){ return 'err:'+String(e); }
"""


def _read_state(tab):
    """读一次 widget 状态，返回 dict；解析失败返回空 dict。"""
    try:
        raw = tab.run_js(_STATE_JS)
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def solve_turnstile_browser(headless=False, timeout=120):
    """打开真实 sign-up 页，全程检测状态（不盲等固定时间）：
      1) 等页面 ready 且 window.turnstile API 就绪
      2) 填占位表单 → 检测 cf-turnstile-response input 挂载
      3) 若页面组件半挂载迟迟不出 challenge iframe，用已知 sitekey 自己 render 兜底
      4) 检测到 challenge iframe 后进 iframe 点 checkbox（每步都检测，出来才动手）
      5) 轮询直到 token（≥80）出现
    每一步独立检测 + 日志，卡在哪一步一目了然。"""
    from DrissionPage import Chromium, ChromiumOptions

    opts = ChromiumOptions()
    opts.auto_port()  # 每个实例独立端口 + 独立临时用户目录（支持并发多开）
    for flag in ("--no-first-run", "--no-sandbox", "--disable-dev-shm-usage",
                 "--disable-background-networking", "--mute-audio",
                 "--disable-gpu", "--window-size=1280,900"):
        opts.set_argument(flag)
    if headless:
        # 真 headless 过不了 Turnstile（Cloudflare 检测无头）。改用「隐形有头」：
        # 有头浏览器保证过检，窗口挪到屏幕外，启动后再 hide()，用户完全看不见。
        opts.set_argument("--window-position=-32000,-32000")
    if os.path.exists(EXTENSION_PATH):
        opts.add_extension(EXTENSION_PATH)
    else:
        log(f"[!] 找不到 turnstilePatch 扩展: {EXTENSION_PATH}")

    browser = Chromium(opts)
    tab = browser.latest_tab
    if headless:
        try:
            tab.set.window.hide()   # Windows 下真正隐藏窗口，进程照常渲染，Turnstile 不受影响
        except Exception:
            pass
    try:
        deadline = time.time() + timeout
        log("浏览器打开 sign-up 页…")
        tab.get(PS_SIGNUP_PAGE)

        # ① 等页面 ready 且 turnstile API 就绪（网络慢，检测到才继续，不盲等）
        while time.time() < deadline:
            st = _read_state(tab)
            if st.get("ready") and st.get("hasApi"):
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("等待页面/turnstile API 就绪超时")
        log("页面就绪，turnstile API 已加载")

        # ② 填占位表单，然后检测 cf-turnstile-response input 是否挂载（不 sleep 后瞎找）
        tab.run_js(_FILL_JS)
        input_seen = False
        while time.time() < deadline:
            st = _read_state(tab)
            if st.get("token"):                      # 极快场景：填完直接就有 token
                log(f"Turnstile 通过（预热即得），token 长度={st['tokenLen']}")
                return st["token"]
            if st.get("hasInput"):
                input_seen = True
                break
            time.sleep(0.5)
        if not input_seen:
            raise TimeoutError("等待 cf-turnstile-response 挂载超时")
        log("检测到 turnstile input 已挂载")

        # ③ 短暂检测原生 challenge iframe 是否自行出现；若半挂载不出，则自己 render 兜底
        render_deadline = min(deadline, time.time() + 12)
        while time.time() < render_deadline:
            st = _read_state(tab)
            if st.get("token"):
                log(f"Turnstile 通过，token 长度={st['tokenLen']}")
                return st["token"]
            if st.get("hasIframe"):
                break
            time.sleep(0.6)
        if not _read_state(tab).get("hasIframe"):
            # 原生组件半挂载没出 iframe —— 用已知 sitekey 自己 render 一个干净 widget
            r = tab.run_js(_RENDER_JS, PS_SITEKEY)
            log(f"原生 widget 未出 iframe，显式 render 兜底: {r}")

        # ④ 检测到 challenge iframe 才进去点 checkbox；⑤ 轮询 token
        while time.time() < deadline:
            st = _read_state(tab)
            if st.get("token"):
                log(f"Turnstile 通过，token 长度={st['tokenLen']}")
                return st["token"]
            # 显式 render 的回调 token
            try:
                cb = str(tab.run_js("return String(window.__ps_token||'')") or "").strip()
                if len(cb) >= 80:
                    log(f"Turnstile 通过（render 回调），token 长度={len(cb)}")
                    return cb
            except Exception:
                pass

            if st.get("hasIframe"):
                iframe = tab.ele("tag:iframe@|src:challenges.cloudflare.com@|src:turnstile", timeout=2)
                if iframe:
                    try:
                        iframe.run_js(_SCREEN_INJECT_JS)
                    except Exception:
                        pass
                    try:
                        body_sr = iframe.ele("tag:body").shadow_root
                        btn = body_sr.ele("tag:input", timeout=2)
                        if btn:
                            btn.click()
                    except Exception:
                        pass
            time.sleep(1.0)
        raise TimeoutError("Turnstile 求解超时（已检测到各阶段状态，token 未生成）")
    finally:
        try:
            browser.quit()
        except Exception:
            pass


def _captcha_post(path, payload):
    """Call a createTask-compatible captcha API and normalize errors."""
    provider_label = {
        "yescaptcha": "YesCaptcha",
        "capmonster": "CapMonster Cloud",
        "capmonstercloud": "CapMonster Cloud",
    }.get(CAPTCHA_PROVIDER.lower(), "2Captcha")
    try:
        response = requests.post(
            f"{CAPTCHA_API_BASE}{path}", json=payload, timeout=30,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"{provider_label} HTTP 请求失败: {e}") from e
    except ValueError as e:
        raise RuntimeError(f"{provider_label} 返回了非 JSON 响应") from e

    if data.get("errorId"):
        code = data.get("errorCode") or f"error-{data['errorId']}"
        description = data.get("errorDescription") or "未知错误"
        raise RuntimeError(f"{provider_label} {code}: {description}")
    return data


def solve_turnstile_2captcha(timeout=None):
    """Create and poll a proxyless Turnstile task through an API provider."""
    provider_label = {
        "yescaptcha": "YesCaptcha",
        "capmonster": "CapMonster Cloud",
        "capmonstercloud": "CapMonster Cloud",
    }.get(CAPTCHA_PROVIDER.lower(), "2Captcha")
    if not CAPTCHA_API_KEY:
        raise RuntimeError(f"captcha_provider={CAPTCHA_PROVIDER}，但未配置 captcha_api_key")

    timeout = CAPTCHA_TIMEOUT if timeout is None else timeout
    created = _captcha_post("/createTask", {
        "clientKey": CAPTCHA_API_KEY,
        "task": {
            "type": "TurnstileTaskProxyless",
            "websiteURL": PS_SIGNUP_PAGE,
            "websiteKey": PS_SITEKEY,
        },
    })
    task_id = created.get("taskId")
    if not task_id:
        raise RuntimeError(f"{provider_label} createTask 未返回 taskId")

    log(f"{provider_label} 任务已创建: {task_id}")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(CAPTCHA_POLL_INTERVAL)
        result = _captcha_post("/getTaskResult", {
            "clientKey": CAPTCHA_API_KEY,
            "taskId": task_id,
        })
        status = result.get("status")
        if status == "processing":
            continue
        if status != "ready":
            raise RuntimeError(f"{provider_label} 返回未知任务状态: {status!r}")
        token = str((result.get("solution") or {}).get("token") or "").strip()
        if not token:
            raise RuntimeError(f"{provider_label} 任务已完成，但未返回 Turnstile token")
        cost = result.get("cost")
        log(f"{provider_label} Turnstile 已完成，token 长度={len(token)}"
            + (f"，费用={cost}" if cost else ""))
        return token
    raise TimeoutError(f"{provider_label} Turnstile 求解超时（任务 {task_id}）")


def solve_turnstile_yescaptcha(timeout=None):
    """Solve Turnstile through YesCaptcha's createTask-compatible API."""
    if not CAPTCHA_API_KEY:
        raise RuntimeError("captcha_provider=yescaptcha，但未配置 captcha_api_key")
    return solve_turnstile_2captcha(timeout=timeout)


def solve_turnstile_capmonster(timeout=None):
    """Solve Turnstile through CapMonster Cloud's compatible task API."""
    if not CAPTCHA_API_KEY:
        raise RuntimeError("captcha_provider=capmonster，但未配置 captcha_api_key")
    return solve_turnstile_2captcha(timeout=timeout)


def solve_turnstile(headless=False, timeout=None):
    """Dispatch Turnstile solving to the configured provider."""
    provider = CAPTCHA_PROVIDER.replace("-", "").replace("_", "")
    if provider in {"2captcha", "2cap"}:
        return solve_turnstile_2captcha(timeout=timeout)
    if provider in {"yescaptcha", "yescap"}:
        return solve_turnstile_yescaptcha(timeout=timeout)
    if provider in {"capmonster", "capmonstercloud"}:
        return solve_turnstile_capmonster(timeout=timeout)
    if provider in {"browser", "local", "extension"}:
        return solve_turnstile_browser(
            headless=headless,
            timeout=120 if timeout is None else timeout,
        )
    raise RuntimeError(f"不支持的 captcha_provider: {CAPTCHA_PROVIDER!r}")


# ── 注册（协议）─────────────────────────────────────────
def register(email, password, turnstile_token):
    s = requests.Session()
    s.headers.update(HEADERS)
    r = s.post(PS_REGISTER, data={
        "email": email,
        "password": password,
        "cf_turnstile_token": turnstile_token,
    }, timeout=30)
    try:
        response_log = dict(r.json())
        if response_log.get("access_token"):
            response_log["access_token"] = "<redacted>"
        log(f"注册响应 {r.status_code}: "
            f"{json.dumps(response_log, ensure_ascii=False)[:300]}")
    except Exception:
        log(f"注册响应 {r.status_code}: <non-JSON body, {len(r.content)} bytes>")
    r.raise_for_status()
    data = r.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"注册未返回 access_token: {data}")
    log("注册成功，access_token 已获取")
    return s, token, data.get("userData", {})


def resend_code(session, access_token):
    """触发发送/重发验证码（注册后不会自动发，必须调一次）。"""
    r = session.post(PS_RESEND, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
    log(f"resend 触发: {r.status_code}")
    return r.ok


def verify_email(session, access_token, code):
    # 关键：字段名是 verificationCode（不是 code），且服务端要 multipart/form-data
    r = session.post(PS_VERIFY_EMAIL,
                     headers={"Authorization": f"Bearer {access_token}"},
                     files={"verificationCode": (None, code)}, timeout=30)
    log(f"验邮箱响应 {r.status_code}: {r.text[:200]}")
    return r.ok


def get_current_user(session, access_token):
    r = session.post(PS_ME, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
    if not r.ok:
        raise RuntimeError(f"/me 失败 {r.status_code}: {r.text[:200]}")
    data = r.json()
    userdata = data.get("userData") or data.get("data") or data
    if not isinstance(userdata, dict):
        raise RuntimeError(f"/me 未返回用户数据: {str(data)[:200]}")
    return userdata


def whoami(session, access_token):
    """向后兼容旧调用；新流程使用 get_current_user 获取最新数据。"""
    try:
        get_current_user(session, access_token)
        return True
    except Exception as e:
        log(f"/me 校验失败: {e}")
        return False


def _first_account_id(userdata):
    subs = userdata.get("associatedSubaccounts") or []
    return next((sub.get("AccountID") for sub in subs if sub.get("AccountID")), None)


def ensure_premium_trial(session, access_token):
    """Claim the free Premium DC trial once and return any account ID in the response."""
    headers = {"Authorization": f"Bearer {access_token}"}
    r = session.get(PS_TRIAL_ELIGIBILITY, headers=headers, timeout=30)
    r.raise_for_status()
    status = r.json()
    if status.get("claimed"):
        log("Premium trial 已领取，跳过重复操作")
        return None

    r = session.post(PS_CLAIM_TRIAL, headers=headers, json={}, timeout=30)
    if not r.ok:
        raise RuntimeError(f"Premium trial 领取失败 {r.status_code}: {r.text[:200]}")
    data = r.json()
    if data.get("success") is False or data.get("error"):
        raise RuntimeError(f"Premium trial 领取失败: {data.get('error') or data}")
    log("Premium trial 领取成功")
    return data.get("account_id")


def activate_trial_and_get_account(session, access_token, tries=5, delay=2.0):
    """Activate the free trial and wait until /me exposes its subaccount."""
    claimed_account_id = ensure_premium_trial(session, access_token)
    userdata = {}
    for attempt in range(1, tries + 1):
        userdata = get_current_user(session, access_token)
        account_id = _first_account_id(userdata) or claimed_account_id
        if account_id:
            return userdata, account_id
        if attempt < tries:
            time.sleep(delay)
    raise RuntimeError("Premium trial 已处理，但 /me 仍未返回 AccountID")


def _auth_headers(access_token):
    return {
        "Authorization": f"Bearer {access_token}",
        "User-Agent": UA,
        "Origin": PS_BASE,
        "Accept": "application/json, text/plain, */*",
        "Referer": f"{PS_BASE}/v2/account/api-keys",
    }


def _json_or_error(response, what):
    try:
        data = response.json()
    except ValueError:
        data = {}
    if not response.ok:
        detail = data.get("error") or data.get("info") or response.text[:200]
        raise RuntimeError(f"{what} 失败 {response.status_code}: {detail}")
    if isinstance(data, dict) and data.get("success") is False:
        raise RuntimeError(f"{what} 失败: {data.get('error') or data}")
    return data


def fetch_service_overview(access_token, account_id):
    headers = _auth_headers(access_token)

    def _overview():
        response = requests.get(
            f"{PS_BASE}/v2/v4/account/{account_id}/services/overview",
            headers=headers, timeout=25,
        )
        response.raise_for_status()
        data = response.json().get("data")
        if not data or "services" not in data:
            raise RuntimeError(f"overview 无数据（trial 可能未激活）: {str(response.text)[:80]}")
        return data

    return _retry(_overview, tries=3, delay=3, what="overview")


def overview_credentials(overview):
    services = overview.get("services") or {}
    shared = services.get("datacenter_shared") or {}
    try:
        total = overview.get("bandwidth")
        total = int(total) if total is not None else None
    except (TypeError, ValueError):
        total = None
    try:
        used = overview.get("bandwidth_used")
        used = int(used) if used is not None else 0
    except (TypeError, ValueError):
        used = 0
    remaining = None if total is None else max(0, total - used)
    expiry = shared.get("expiration_time") or overview.get("bandwidth_period_end")
    try:
        expiry = int(expiry) if expiry else None
    except (TypeError, ValueError):
        expiry = None
    days = None
    if expiry:
        days = max(0, int((expiry - time.time()) // 86400))
    return {
        "proxy_username": shared.get("proxy_username") or "",
        "proxy_password": shared.get("proxy_password") or "",
        "proxy_amount": shared.get("proxy_amount"),
        "expiration_time": expiry,
        "days_remaining": days,
        "bandwidth_total": total,
        "bandwidth_used": used,
        "bandwidth_remaining": remaining,
        "bandwidth_period_end": overview.get("bandwidth_period_end"),
        "account_key": overview.get("key") or "",
        "is_trial": overview.get("is_trial"),
        "proxy_credentials_enabled": overview.get("proxy_credentials_enabled"),
        "max_connections": overview.get("max_connections"),
        "usage_synced_at": int(time.time()),
    }


def fetch_accounts_summary(session, access_token):
    response = session.get(
        PS_ACCOUNTS_SUMMARY, headers=_auth_headers(access_token), timeout=25,
    )
    data = _json_or_error(response, "accounts-summary")
    payload = data.get("data") if isinstance(data, dict) else data
    if isinstance(payload, dict):
        return payload.get("accounts") or []
    return payload if isinstance(payload, list) else []


def fetch_permission_context(session, access_token):
    response = session.get(PS_PERM_CTX, headers=_auth_headers(access_token), timeout=25)
    data = _json_or_error(response, "permission-context")
    if not isinstance(data, dict):
        return dict(PERMISSION_CATALOG)
    allowed = data.get("allowed_permissions") or list(DEFAULT_API_PERMISSIONS)
    structure = data.get("structure") or PERMISSION_CATALOG["structure"]
    return {"allowed_permissions": allowed, "structure": structure}


def create_api_key(session, access_token, account_id, name=API_KEY_NAME, permissions=None):
    payload = {
        "name": name or API_KEY_NAME,
        "permissions": permissions or list(DEFAULT_API_PERMISSIONS),
        "allowed_subaccounts": [account_id] if account_id else [],
        "allowed_ips": [],
        "expires_at": None,
    }
    response = session.post(
        PS_API_KEYS,
        headers={**_auth_headers(access_token), "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    data = _json_or_error(response, "创建 API 密钥")
    item = data.get("data") if isinstance(data, dict) else data
    if not isinstance(item, dict) or not item.get("token"):
        raise RuntimeError("创建 API 密钥未返回 token")
    return {
        "id": item.get("id") or "",
        "token": item.get("token") or "",
        "name": item.get("name") or payload["name"],
        "permissions": item.get("permissions") or payload["permissions"],
        "allowed_subaccounts": item.get("allowed_subaccounts") or payload["allowed_subaccounts"],
        "allowed_ips": item.get("allowed_ips") or [],
        "expires_at": item.get("expires_at"),
        "created_at": item.get("created_at"),
        "is_active": item.get("is_active", True),
    }


def update_api_key(session, access_token, key_id, **fields):
    body = {key: value for key, value in fields.items() if value is not None}
    if not body:
        raise RuntimeError("没有可更新的 API 密钥字段")
    response = session.put(
        f"{PS_API_KEYS}/{key_id}",
        headers={**_auth_headers(access_token), "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    data = _json_or_error(response, "更新 API 密钥")
    item = data.get("data") if isinstance(data, dict) else data
    return item if isinstance(item, dict) else {}


def provision_api_key(session, access_token, account_id, permissions=None, name=API_KEY_NAME, existing=None):
    existing = existing if isinstance(existing, dict) else {}
    perms = permissions or list(DEFAULT_API_PERMISSIONS)
    key_id = str(existing.get("id") or "").strip()
    if key_id:
        updated = update_api_key(
            session, access_token, key_id,
            name=name or existing.get("name") or API_KEY_NAME,
            permissions=perms,
            allowed_subaccounts=[account_id] if account_id else existing.get("allowed_subaccounts") or [],
            allowed_ips=existing.get("allowed_ips") or [],
        )
        merged = dict(existing)
        merged.update({key: updated[key] for key in updated if key != "token"})
        merged["permissions"] = updated.get("permissions") or perms
        merged["token"] = existing.get("token") or merged.get("token") or ""
        return merged
    return create_api_key(session, access_token, account_id, name=name, permissions=perms)


# ── 拉取免费 datacenter 代理 ────────────────────────────
SUPPORTED_PROXY_PROTOCOLS = ("http", "socks5h")


def normalize_proxy_protocol(value, default="http"):
    """Normalize UI/config/query protocol to url scheme http or socks5h."""
    text = str(value or "").strip().lower()
    if text in {"", "default"}:
        text = str(default or "http").strip().lower()
    if text in {"socks5", "socks", "socks5h"}:
        return "socks5h"
    if text in {"http", "https"}:
        return "http"
    raise ValueError("代理协议仅支持 http 或 socks5h")


def proxyscrape_protocol_param(scheme):
    """ProxyScrape list API accepts http/socks5 (not socks5h)."""
    return "socks5" if normalize_proxy_protocol(scheme) == "socks5h" else "http"


def list_proxy_hosts(access_token, account_id, protocol="http"):
    headers = _auth_headers(access_token)
    api_protocol = proxyscrape_protocol_param(protocol)

    def _list():
        response = requests.get(
            f"{PS_BASE}/v2/v4/account/{account_id}/datacenter_shared/proxy-list",
            headers=headers, params={"protocol": api_protocol, "format": "normal"}, timeout=25,
        )
        response.raise_for_status()
        return response.text

    text = _retry(_list, tries=3, delay=3, what="proxy-list")
    proxies = [line.strip() for line in text.split() if ":" in line]
    if not proxies:
        raise RuntimeError("proxy-list 为空")
    return proxies


def fetch_proxies(access_token, account_id, protocol="http"):
    """注册后 Premium trial 自带 100 个 datacenter 共享代理。
    从 overview 拿账密，从 proxy-list 端点拿 ip:port 列表。"""
    extras = overview_credentials(fetch_service_overview(access_token, account_id))
    user, pwd = extras["proxy_username"], extras["proxy_password"]
    proxies = list_proxy_hosts(access_token, account_id, protocol=protocol)
    return user, pwd, proxies, extras


def _format_proxy_url(user, pwd, ip, protocol="http"):
    scheme = normalize_proxy_protocol(protocol)
    host = str(ip or "").strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    raw = f"{user}:{pwd}@{host}".strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        rest = raw.split("://", 1)[1]
        return f"{scheme}://{rest}"
    return f"{scheme}://{raw}"


def _append_private(path, text):
    """Append UTF-8 text while keeping credential-bearing files owner-only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(text)
    os.chmod(path, 0o600)


def save_proxies(user, pwd, proxies, path, protocol="http"):
    """追加写入本轮代理文件，格式 {http|socks5h}://user:pass@ip:port。"""
    with _file_lock:
        text = "".join(f"{_format_proxy_url(user, pwd, ip, protocol=protocol)}\n" for ip in proxies)
        _append_private(path, text)


# ── 单个账号注册（并发 worker）───────────────────────────
def save_account(rec, path):
    with _file_lock:
        _append_private(path, json.dumps(rec, ensure_ascii=False) + "\n")


def _register_once(headless, node_file):
    """单次尝试：建邮箱→打码→注册→验证→拉代理。返回 rec（不落盘账号）。
    建邮箱/打码/注册任一失败抛异常，交给外层重试。"""
    password = "Ps" + "".join(random.choices(string.ascii_letters + string.digits, k=10)) + "!9"
    email, _ = create_mailbox()                    # 失败抛异常 → 外层重试
    token = solve_turnstile(headless=headless)     # 失败抛异常 → 外层重试
    session, access_token, userdata = register(email, password, token)  # 同上

    verified = False
    try:
        resend_code(session, access_token)
        code = wait_mail_code(email, timeout=180)
        verified = verify_email(session, access_token, code)
    except Exception as e:
        log(f"[!] 邮箱验证环节: {e}（账号已注册，token 有效）")

    # 邮箱验证后显式领取 Premium trial，再拉取凭证 / API 密钥 / 代理列表。
    p_user = p_pass = ""
    p_count = 0
    account_id = None
    trial_claimed = False
    extras = {}
    api_key = {}
    account_summary = None
    if not verified:
        log("邮箱未验证，trial 未激活，跳过拉代理")
    else:
        try:
            userdata, account_id = activate_trial_and_get_account(session, access_token)
            trial_claimed = True
            p_user, p_pass, plist, extras = fetch_proxies(access_token, account_id)
            save_proxies(p_user, p_pass, plist, node_file)
            p_count = len(plist)
            extras = dict(extras)
            extras["proxy_ips"] = plist
            log(f"拉取代理 {p_count} 个")
            try:
                summary = fetch_accounts_summary(session, access_token)
                account_summary = next(
                    (item for item in summary if item.get("id") == account_id),
                    summary[0] if summary else None,
                )
            except Exception as error:
                log(f"[!] accounts-summary: {error}")
            try:
                context = fetch_permission_context(session, access_token)
                allowed = context.get("allowed_permissions") or list(DEFAULT_API_PERMISSIONS)
                api_key = provision_api_key(
                    session, access_token, account_id, permissions=allowed,
                )
                log("API 密钥已创建，权限 %d 项" % len(api_key.get("permissions") or []))
            except Exception as error:
                log(f"[!] 创建 API 密钥失败: {error}")
        except Exception as e:
            log(f"[!] 拉代理失败: {e}")

    record = {
        "email": email, "password": password,
        "access_token": access_token, "userData": userdata,
        "verified": verified,
        "trial_claimed": trial_claimed, "account_id": account_id,
        "proxy_username": p_user, "proxy_password": p_pass, "proxy_count": p_count,
        "api_key": api_key,
        "account_summary": account_summary,
        "ts": int(time.time()),
    }
    record.update({key: value for key, value in extras.items() if value is not None})
    return record


def register_one(idx, headless, acc_file, node_file, max_attempts=3):
    """账号级重试：任一步异常或没拿到代理，就换新邮箱重来，直到成功或用尽。
    成功（拿到代理）落盘并返回；用尽则落盘最后一次半成品（token 有效、无代理）。"""
    _tls.tag = f" #{idx}"
    last = None
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            log(f"—— 第 {attempt}/{max_attempts} 次尝试 ——")
        try:
            rec = _register_once(headless, node_file)
        except Exception as e:
            log(f"[x] 本次尝试失败: {str(e)[:120]}")
            rec = None

        if rec:
            last = rec
            if rec.get("proxy_count", 0) > 0:
                save_account(rec, acc_file)
                log(f"[✓] 完成  verified={rec['verified']}  proxies={rec['proxy_count']}  {rec['email']}")
                return rec
            log("注册成功但未拿到代理，换邮箱重试")

    if last:
        save_account(last, acc_file)
        log(f"[!] 重试用尽，存半成品  verified={last['verified']}  proxies={last.get('proxy_count',0)}  {last['email']}")
    else:
        log(f"[x] {max_attempts} 次尝试均失败，放弃 #{idx}")
    return last


# ── 启动引导 ────────────────────────────────────────────
def _ask(prompt, default):
    try:
        v = input(prompt).strip()
    except EOFError:
        v = ""
    return v or default


def guide():
    print("=" * 52)
    print("   ProxyScrape 批量注册机  ·  打码走协议")
    print(f"   Turnstile: {CAPTCHA_PROVIDER}   注册/收信/验证全走 HTTP")
    print(f"   临时邮箱: {MAIL_PROVIDER}   账号→account/  代理→node/")
    print("=" * 52)
    try:
        count = int(_ask("① 注册数量        [默认 5，输 0 退出]: ", "5"))
    except ValueError:
        count = 5
    try:
        threads = int(_ask("② 并发线程        [默认 3]: ", "3"))
    except ValueError:
        threads = 3
    hl = _ask("③ 隐藏浏览器窗口   [Y/n，仅 browser 模式]: ", "Y").lower()
    headless = not hl.startswith("n")
    threads = max(1, min(threads, count, 8))  # 并发上限 8，别把机器压垮
    print("-" * 52)
    display = "2Captcha API" if CAPTCHA_PROVIDER == "2captcha" else (
        "隐藏窗口" if headless else "显示窗口"
    )
    print(f"  → 注册 {count} 个 · 并发 {threads} · {display}")
    print("-" * 52)
    return count, threads, headless


def run_round(count, threads, headless):
    # 每轮独立文件（时间戳命名），不追加旧文件
    ts = time.strftime("%Y%m%d_%H%M%S")
    acc_file = os.path.join(_ACCOUNT_DIR, f"accounts_{ts}.jsonl")
    node_file = os.path.join(_NODE_DIR, f"proxies_{ts}.txt")
    t0 = time.time()
    ok = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(register_one, i + 1, headless, acc_file, node_file): i + 1
                for i in range(count)}
        for fu in as_completed(futs):
            try:
                r = fu.result()
            except Exception as e:
                r = None
                with _print_lock:
                    print(f"[worker error] {e}", flush=True)
            if r:
                ok.append(r)

    dt = time.time() - t0
    total_proxies = sum(r.get("proxy_count", 0) for r in ok)
    print("\n" + "=" * 52)
    print(f"  完成 {len(ok)}/{count}  ·  用时 {dt:.0f}s  ·  代理共 {total_proxies} 个")
    print(f"  账号 → account/{os.path.basename(acc_file)}")
    print(f"  代理 → node/{os.path.basename(node_file)}")
    for r in ok:
        print(f"    {r['email']}  |  {r['password']}  |  verified={r['verified']}  |  proxies={r.get('proxy_count',0)}")
    print("=" * 52 + "\n")


def main():
    # 跑完一轮不退出，回到引导继续；注册数量输 0 退出
    while True:
        count, threads, headless = guide()
        if count <= 0:
            print("已退出。")
            return 0
        run_round(count, threads, headless)


if __name__ == "__main__":
    sys.exit(main())
