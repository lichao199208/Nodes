# -*- coding: utf-8 -*-
"""Authenticated web dashboard for the Nodes registration worker."""

import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash
import requests

import pool
import platform_store
import proxy_quality
import proxyscrape_register as worker


BASE_DIR = Path(__file__).resolve().parent
ACCOUNT_DIR = Path(os.environ.get("NODES_ACCOUNT_DIR", BASE_DIR / "account"))
NODE_DIR = Path(os.environ.get("NODES_NODE_DIR", BASE_DIR / "node"))
WEB_DATA_DIR = Path(os.environ.get("NODES_WEB_DATA_DIR", BASE_DIR / "web-data"))
CONFIG_FILE = Path(os.environ.get("NODES_CONFIG_FILE", BASE_DIR / "config.local.json"))
TASKS_FILE = WEB_DATA_DIR / "tasks.json"

ACCOUNT_DIR.mkdir(parents=True, exist_ok=True)
NODE_DIR.mkdir(parents=True, exist_ok=True)
WEB_DATA_DIR.mkdir(parents=True, exist_ok=True)


def _read_config():
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


SETTINGS_KEYS = (
    "mail_provider",
    "mail_api_base",
    "mail_api_key",
    "mail_type",
    "mail_suffix",
    "mail_domain",
    "yyds_api_key",
    "yyds_domain",
    "captcha_provider",
    "captcha_api_key",
    "captcha_api_base",
    "captcha_timeout",
    "captcha_poll_interval",
    "turnstile_extension_path",
    "proxy_enabled",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "export_proxy_protocol",
    "resin_gateway_host",
    "resin_gateway_public_host",
    "resin_gateway_port",
    "resin_gateway_platform",
    "pull_api_base",
    "pull_api_user",
    "pull_api_pass",
    "pull_api_shuliang",
    "pull_api_id",
    "proxy_quality_enabled",
    "proxy_max_latency_ms",
    "proxy_exclude_countries",
    "proxy_arp_check_enabled",
    "proxy_arp_probe_url",
    "arp_publish_url",
    "arp_publish_token",
    "proxy_quality_workers",
    "proxy_quality_cache_ttl_sec",
    "quality_profile_id",
    "export_quality_profile",
)

QUALITY_FLAT_KEYS = (
    "proxy_quality_enabled",
    "proxy_max_latency_ms",
    "proxy_exclude_countries",
    "proxy_arp_check_enabled",
    "proxy_arp_probe_url",
    "arp_publish_url",
    "arp_publish_token",
    "proxy_quality_workers",
    "proxy_quality_cache_ttl_sec",
)

BUILTIN_QUALITY_PROFILES = {
    "default": {
        "id": "default",
        "name": "默认",
        "proxy_quality_enabled": True,
        "proxy_max_latency_ms": 3000,
        "proxy_exclude_countries": "US",
        "proxy_arp_check_enabled": True,
        "proxy_arp_probe_url": "https://firefly-3p.ff.adobe.io/",
        "arp_publish_url": "",
        "arp_publish_token": "",
        "proxy_quality_workers": 16,
        "proxy_quality_cache_ttl_sec": 600,
    },
    "arp-strict": {
        "id": "arp-strict",
        "name": "ARP 严格",
        "proxy_quality_enabled": True,
        "proxy_max_latency_ms": 2000,
        "proxy_exclude_countries": "US",
        "proxy_arp_check_enabled": True,
        "proxy_arp_probe_url": "https://firefly-3p.ff.adobe.io/",
        "arp_publish_url": "",
        "arp_publish_token": "",
        "proxy_quality_workers": 16,
        "proxy_quality_cache_ttl_sec": 600,
    },
    "geo-only": {
        "id": "geo-only",
        "name": "仅地理/延迟",
        "proxy_quality_enabled": True,
        "proxy_max_latency_ms": 3000,
        "proxy_exclude_countries": "US",
        "proxy_arp_check_enabled": False,
        "proxy_arp_probe_url": "https://firefly-3p.ff.adobe.io/",
        "arp_publish_url": "",
        "arp_publish_token": "",
        "proxy_quality_workers": 16,
        "proxy_quality_cache_ttl_sec": 600,
    },
}

# Logical groups for GET/PUT; file remains flat JSON.
SETTINGS_GROUPS = {
    "sources": (
        "pull_api_base",
        "pull_api_user",
        "pull_api_pass",
        "pull_api_shuliang",
        "pull_api_id",
        "export_proxy_protocol",
    ),
    "quality": (
        "proxy_quality_enabled",
        "proxy_max_latency_ms",
        "proxy_exclude_countries",
        "proxy_arp_check_enabled",
        "proxy_arp_probe_url",
        "arp_publish_url",
        "arp_publish_token",
        "proxy_quality_workers",
        "proxy_quality_cache_ttl_sec",
        "quality_profile_id",
        "export_quality_profile",
    ),
    "registration": (
        "mail_provider",
        "mail_api_base",
        "mail_api_key",
        "mail_type",
        "mail_suffix",
        "mail_domain",
        "yyds_api_key",
        "yyds_domain",
        "captcha_provider",
        "captcha_api_key",
        "captcha_api_base",
        "captcha_timeout",
        "captcha_poll_interval",
        "turnstile_extension_path",
        "proxy_enabled",
        "http_proxy",
        "https_proxy",
        "no_proxy",
    ),
    "exports": (
        "export_proxy_protocol",
        "export_quality_profile",
        "resin_gateway_host",
        "resin_gateway_public_host",
        "resin_gateway_port",
        "resin_gateway_platform",
    ),
}


def _mask_secret(value):
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 4:
        return "*" * len(text)
    return f"{text[:2]}{'*' * max(4, len(text) - 4)}{text[-2:]}"


def _pull_api_int(value, default, minimum=1, maximum=100000):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


def _public_settings(config):
    return {
        "mail_provider": str(config.get("mail_provider") or "yunxin"),
        "mail_api_base": str(config.get("mail_api_base") or ""),
        "mail_api_key": str(config.get("mail_api_key") or ""),
        "mail_type": str(config.get("mail_type") or "mail"),
        "mail_suffix": str(config.get("mail_suffix") or "mail.com"),
        "mail_domain": str(config.get("mail_domain") or ""),
        "yyds_api_key": str(config.get("yyds_api_key") or ""),
        "yyds_domain": str(config.get("yyds_domain") or ""),
        "captcha_provider": str(config.get("captcha_provider") or "2captcha"),
        "captcha_api_key": str(config.get("captcha_api_key") or ""),
        "captcha_api_base": str(config.get("captcha_api_base") or "https://api.2captcha.com"),
        "captcha_timeout": int(config.get("captcha_timeout") or 180),
        "captcha_poll_interval": int(float(config.get("captcha_poll_interval") or 5)),
        "turnstile_extension_path": str(config.get("turnstile_extension_path") or ""),
        "proxy_enabled": _as_bool(config.get("proxy_enabled")),
        "http_proxy": str(config.get("http_proxy") or ""),
        "https_proxy": str(config.get("https_proxy") or ""),
        "no_proxy": str(config.get("no_proxy") or "localhost,127.0.0.1"),
        "export_proxy_protocol": _export_protocol_from_config(config),
        "resin_gateway_host": str(config.get("resin_gateway_host") or pool.DEFAULT_GATEWAY_HOST).strip() or pool.DEFAULT_GATEWAY_HOST,
        "resin_gateway_public_host": str(config.get("resin_gateway_public_host") or "").strip(),
        "resin_gateway_port": max(1, min(65535, pool._as_int(config.get("resin_gateway_port"), pool.DEFAULT_GATEWAY_PORT))),
        "resin_gateway_platform": str(config.get("resin_gateway_platform") or pool.DEFAULT_PLATFORM).strip() or pool.DEFAULT_PLATFORM,
        "pull_api_base": str(config.get("pull_api_base") or "").strip(),
        "pull_api_user": str(config.get("pull_api_user") or "").strip(),
        "pull_api_pass": str(config.get("pull_api_pass") or ""),
        "pull_api_shuliang": _pull_api_int(config.get("pull_api_shuliang"), 100, 1, 10000),
        "pull_api_id": _pull_api_int(config.get("pull_api_id"), 1, 1, 100000),
        "proxy_quality_enabled": proxy_quality._as_bool(config.get("proxy_quality_enabled"), True),
        "proxy_max_latency_ms": int(proxy_quality.quality_settings(config)["max_latency_ms"]),
        "proxy_exclude_countries": ",".join(proxy_quality.quality_settings(config)["exclude_countries"]),
        "proxy_arp_check_enabled": proxy_quality._as_bool(config.get("proxy_arp_check_enabled"), True),
        "proxy_arp_probe_url": str(config.get("proxy_arp_probe_url") or proxy_quality.DEFAULT_ARP_PROBE_URL).strip(),
        "arp_publish_url": str(config.get("arp_publish_url") or "").strip(),
        "arp_publish_token": str(config.get("arp_publish_token") or ""),
        "proxy_quality_workers": int(proxy_quality.quality_settings(config)["workers"]),
        "proxy_quality_cache_ttl_sec": int(proxy_quality.quality_settings(config)["cache_ttl_sec"]),
        "proxy_quality_version": int(config.get("proxy_quality_version") or 0),
        "proxy_quality_updated_at": str(config.get("proxy_quality_updated_at") or ""),
        "quality_profile_id": str(config.get("quality_profile_id") or "default").strip() or "default",
        "export_quality_profile": str(
            config.get("export_quality_profile") or config.get("quality_profile_id") or "default"
        ).strip() or "default",
    }


def _profile_id_clean(value, default="default"):
    text = str(value or "").strip().lower().replace(" ", "-")
    text = re.sub(r"[^a-z0-9_\-]+", "", text)
    return text or default


def _quality_fields_dict(source):
    data = source if isinstance(source, dict) else {}
    qcfg = proxy_quality.quality_settings(data)
    return {
        "proxy_quality_enabled": bool(qcfg["enabled"]),
        "proxy_max_latency_ms": int(qcfg["max_latency_ms"]),
        "proxy_exclude_countries": ",".join(qcfg["exclude_countries"]),
        "proxy_arp_check_enabled": bool(qcfg["arp_check_enabled"]),
        "proxy_arp_probe_url": str(data.get("proxy_arp_probe_url") or qcfg["arp_probe_url"]).strip(),
        "arp_publish_url": str(data.get("arp_publish_url") or "").strip(),
        "arp_publish_token": str(data.get("arp_publish_token") or ""),
        "proxy_quality_workers": int(qcfg["workers"]),
        "proxy_quality_cache_ttl_sec": int(qcfg["cache_ttl_sec"]),
    }


def _ensure_quality_profiles(config):
    """Return profiles dict, seeding builtins + mirroring flat keys into active profile."""
    cfg = config if isinstance(config, dict) else {}
    raw = cfg.get("quality_profiles")
    profiles = dict(raw) if isinstance(raw, dict) else {}
    for pid, preset in BUILTIN_QUALITY_PROFILES.items():
        if pid not in profiles or not isinstance(profiles.get(pid), dict):
            profiles[pid] = dict(preset)
        else:
            merged = dict(preset)
            merged.update({k: profiles[pid].get(k, preset.get(k)) for k in (*QUALITY_FLAT_KEYS, "name", "id", "version", "updated_at")})
            merged["id"] = pid
            profiles[pid] = merged
    active = _profile_id_clean(cfg.get("quality_profile_id"), "default")
    if active not in profiles:
        active = "default"
    # Mirror current flat config into the active profile so legacy edits stay visible.
    flat = _quality_fields_dict(cfg)
    active_row = dict(profiles.get(active) or BUILTIN_QUALITY_PROFILES["default"])
    active_row.update(flat)
    active_row["id"] = active
    active_row["name"] = active_row.get("name") or active
    active_row["version"] = int(cfg.get("proxy_quality_version") or active_row.get("version") or 0)
    active_row["updated_at"] = str(cfg.get("proxy_quality_updated_at") or active_row.get("updated_at") or "")
    profiles[active] = active_row
    return profiles, active


def _profiles_public(config):
    profiles, active = _ensure_quality_profiles(config)
    export_id = _profile_id_clean(
        config.get("export_quality_profile") or active, active,
    )
    if export_id not in profiles:
        export_id = active
    return {
        "active_id": active,
        "export_id": export_id,
        "profiles": [
            {
                "id": pid,
                "name": row.get("name") or pid,
                "version": int(row.get("version") or 0),
                "updated_at": str(row.get("updated_at") or ""),
                "builtin": pid in BUILTIN_QUALITY_PROFILES,
                **{key: row.get(key) for key in QUALITY_FLAT_KEYS},
            }
            for pid, row in sorted(profiles.items(), key=lambda item: item[0])
            if isinstance(row, dict)
        ],
    }


def _config_for_quality(config=None, rule_id=None):
    """Flat config with quality fields resolved from the requested profile."""
    cfg = dict(config if isinstance(config, dict) else _read_config())
    profiles, active = _ensure_quality_profiles(cfg)
    wanted = _profile_id_clean(rule_id or cfg.get("export_quality_profile") or active, active)
    row = profiles.get(wanted) or profiles.get(active) or BUILTIN_QUALITY_PROFILES["default"]
    for key in QUALITY_FLAT_KEYS:
        if key in row:
            cfg[key] = row[key]
    cfg["quality_profile_id"] = wanted
    return cfg


def _apply_profile_to_config(next_config, profile_id, fields, bump_version=True):
    pid = _profile_id_clean(profile_id, "default")
    profiles, _active = _ensure_quality_profiles(next_config)
    row = dict(profiles.get(pid) or BUILTIN_QUALITY_PROFILES.get(pid) or {"id": pid, "name": pid})
    row.update(_quality_fields_dict({**row, **fields}))
    row["id"] = pid
    row["name"] = str(fields.get("name") or row.get("name") or pid)
    if bump_version:
        try:
            row["version"] = int(row.get("version") or 0) + 1
        except (TypeError, ValueError):
            row["version"] = 1
        row["updated_at"] = datetime.now(timezone.utc).isoformat()
    profiles[pid] = row
    next_config["quality_profiles"] = profiles
    next_config["quality_profile_id"] = pid
    for key in QUALITY_FLAT_KEYS:
        next_config[key] = row[key]
    if bump_version:
        next_config["proxy_quality_version"] = int(row["version"])
        next_config["proxy_quality_updated_at"] = row["updated_at"]
    return row


def _settings_for_group(config, group):
    public = _public_settings(config)
    keys = SETTINGS_GROUPS.get(group)
    if not keys:
        raise ValueError(f"未知配置分组: {group}")
    return {key: public[key] for key in keys if key in public}


def _is_local_shortcircuit_base(base):
    """True when pull_api_base points at this Nodes /api (avoid recursive HTTP)."""
    base_l = str(base or "").strip().lower()
    if not base_l:
        return False
    # Historical 8892 compat listener — always local pool.
    if ":8892/" in base_l or base_l.rstrip("/").endswith(":8892") or ":8892?" in base_l:
        return True
    local_hosts = ("127.0.0.1", "localhost", "[::1]", "::1")
    if any(host in base_l for host in local_hosts):
        stripped = base_l.rstrip("/")
        if stripped.endswith("/api") or "/nodes/api" in stripped:
            return True
    return False


def _export_protocol_from_config(config=None):
    cfg = config if isinstance(config, dict) else _read_config()
    try:
        return worker.normalize_proxy_protocol(cfg.get("export_proxy_protocol"), default="http")
    except ValueError:
        return "http"


def _resolve_export_protocol(override=None):
    if override is not None and str(override).strip():
        return worker.normalize_proxy_protocol(override, default=_export_protocol_from_config())
    return _export_protocol_from_config()


def _clean_url(value, field):
    text = str(value or "").strip()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        raise ValueError(f"{field} 必须以 http:// 或 https:// 开头")
    return text.rstrip("/")


def _apply_settings(payload):
    if TASK_STORE.active():
        raise RuntimeError("有注册任务正在运行，请结束后再改配置")
    current = _read_config()
    next_config = dict(current)
    data = payload if isinstance(payload, dict) else {}
    group = str(data.get("group") or "").strip().lower()
    if group:
        if group not in SETTINGS_GROUPS:
            raise ValueError(f"未知配置分组: {group}")
        allowed = set(SETTINGS_GROUPS[group])
        incoming = {key: data[key] for key in SETTINGS_KEYS if key in data and key in allowed}
    else:
        incoming = {key: data[key] for key in SETTINGS_KEYS if key in data}
    if not incoming:
        raise ValueError("没有可保存的配置项")

    merged = _public_settings({**current, **incoming})

    mail_provider = str(merged["mail_provider"] or "yunxin").strip().lower()
    if mail_provider not in {"yunxin", "yyds"}:
        raise ValueError("邮箱提供方只能是 yunxin 或 yyds")
    captcha_provider = str(merged["captcha_provider"] or "2captcha").strip().lower()
    if captcha_provider not in {"2captcha", "yescaptcha", "browser"}:
        raise ValueError("打码方式只能是 2captcha、yescaptcha 或 browser")

    timeout = int(merged["captcha_timeout"])
    poll = int(merged["captcha_poll_interval"])
    if not 30 <= timeout <= 600:
        raise ValueError("打码超时必须在 30-600 秒")
    if not 5 <= poll <= 60:
        raise ValueError("打码轮询间隔必须在 5-60 秒")

    # Only rewrite registration/mail/captcha keys when they were submitted.
    mail_keys = {
        "mail_provider", "mail_api_base", "mail_api_key", "mail_type", "mail_suffix",
        "mail_domain", "yyds_api_key", "yyds_domain",
    }
    captcha_keys = {
        "captcha_provider", "captcha_api_key", "captcha_api_base", "captcha_timeout",
        "captcha_poll_interval", "turnstile_extension_path",
    }
    egress_keys = {"proxy_enabled", "http_proxy", "https_proxy", "no_proxy"}
    mail_touch = bool(set(incoming) & mail_keys) or (not group and bool(set(incoming) & set(SETTINGS_GROUPS["registration"])))
    captcha_touch = bool(set(incoming) & captcha_keys) or (not group and bool(set(incoming) & set(SETTINGS_GROUPS["registration"])))
    egress_touch = bool(set(incoming) & egress_keys) or (not group and bool(set(incoming) & set(SETTINGS_GROUPS["registration"])))
    # Flat PUT without group still updates the whole registration block when any registration key is present.
    if not group and bool(set(incoming) & set(SETTINGS_GROUPS["registration"])):
        mail_touch = captcha_touch = egress_touch = True

    if mail_touch:
        next_config["mail_provider"] = mail_provider
        next_config["mail_api_base"] = _clean_url(merged["mail_api_base"], "邮箱 API 地址")
        next_config["mail_api_key"] = str(merged["mail_api_key"] or "").strip()
        next_config["mail_type"] = str(merged["mail_type"] or "mail").strip() or "mail"
        next_config["mail_suffix"] = str(merged["mail_suffix"] or "mail.com").strip() or "mail.com"
        next_config["mail_domain"] = str(merged["mail_domain"] or "").strip()
        next_config["yyds_api_key"] = str(merged["yyds_api_key"] or "").strip()
        next_config["yyds_domain"] = str(merged["yyds_domain"] or "").strip()
        if mail_provider == "yunxin" and not next_config["mail_api_base"]:
            raise ValueError("云芯邮箱需要填写 API 地址")
    if captcha_touch:
        next_config["captcha_provider"] = captcha_provider
        next_config["captcha_api_key"] = str(merged["captcha_api_key"] or "").strip()
        default_captcha_base = "https://api.yescaptcha.com" if captcha_provider == "yescaptcha" else "https://api.2captcha.com"
        next_config["captcha_api_base"] = _clean_url(merged["captcha_api_base"], "打码 API 地址") or default_captcha_base
        next_config["captcha_timeout"] = timeout
        next_config["captcha_poll_interval"] = poll
        next_config["turnstile_extension_path"] = str(merged["turnstile_extension_path"] or "").strip()
        if captcha_provider in {"2captcha", "yescaptcha"} and not next_config["captcha_api_key"]:
            raise ValueError(("YesCaptcha" if captcha_provider == "yescaptcha" else "2Captcha") + " 需要填写 API Key")
    if egress_touch:
        next_config["proxy_enabled"] = _as_bool(merged["proxy_enabled"])
        next_config["http_proxy"] = str(merged["http_proxy"] or "").strip()
        next_config["https_proxy"] = str(merged["https_proxy"] or "").strip()
        next_config["no_proxy"] = str(merged["no_proxy"] or "localhost,127.0.0.1").strip() or "localhost,127.0.0.1"
        if next_config["http_proxy"]:
            _clean_url(next_config["http_proxy"], "HTTP 代理")
        if next_config["https_proxy"]:
            _clean_url(next_config["https_proxy"], "HTTPS 代理")

    if "export_proxy_protocol" in incoming:
        next_config["export_proxy_protocol"] = worker.normalize_proxy_protocol(
            merged.get("export_proxy_protocol"), default="http",
        )

    gateway_keys = {
        "resin_gateway_host", "resin_gateway_public_host",
        "resin_gateway_port", "resin_gateway_platform",
    }
    if gateway_keys & set(incoming):
        host = str(merged.get("resin_gateway_host") or pool.DEFAULT_GATEWAY_HOST).strip() or pool.DEFAULT_GATEWAY_HOST
        public_host = str(merged.get("resin_gateway_public_host") or "").strip()
        platform = str(merged.get("resin_gateway_platform") or pool.DEFAULT_PLATFORM).strip() or pool.DEFAULT_PLATFORM
        next_config["resin_gateway_host"] = host
        next_config["resin_gateway_public_host"] = public_host
        next_config["resin_gateway_port"] = max(
            1, min(65535, pool._as_int(merged.get("resin_gateway_port"), pool.DEFAULT_GATEWAY_PORT)),
        )
        next_config["resin_gateway_platform"] = platform

    if "pull_api_base" in incoming or "pull_api_user" in incoming or "pull_api_pass" in incoming \
            or "pull_api_shuliang" in incoming or "pull_api_id" in incoming:
        pull_base = str(merged.get("pull_api_base") or "").strip()
        if pull_base:
            pull_base = _clean_url(pull_base, "API 拉代理地址")
        next_config["pull_api_base"] = pull_base
        next_config["pull_api_user"] = str(merged.get("pull_api_user") or "").strip()
        next_config["pull_api_pass"] = str(merged.get("pull_api_pass") or "")
        next_config["pull_api_shuliang"] = _pull_api_int(merged.get("pull_api_shuliang"), 100, 1, 10000)
        next_config["pull_api_id"] = _pull_api_int(merged.get("pull_api_id"), 1, 1, 100000)

    quality_keys = set(QUALITY_FLAT_KEYS)
    profile_keys = {"quality_profile_id", "export_quality_profile"}
    if (quality_keys | profile_keys) & set(incoming):
        requested_profile = _profile_id_clean(
            incoming.get("quality_profile_id")
            if "quality_profile_id" in incoming
            else next_config.get("quality_profile_id") or "default",
            "default",
        )

        if quality_keys & set(incoming):
            field_source = {**current, **merged}
            arp_probe = str(field_source.get("proxy_arp_probe_url") or "").strip()
            if arp_probe:
                arp_probe = _clean_url(arp_probe, "ARP 探测地址")
            field_source["proxy_arp_probe_url"] = arp_probe or proxy_quality.DEFAULT_ARP_PROBE_URL
            publish_url = str(field_source.get("arp_publish_url") or "").strip()
            if publish_url:
                publish_url = _clean_url(publish_url, "ARP publish 地址")
            field_source["arp_publish_url"] = publish_url
            row = _apply_profile_to_config(next_config, requested_profile, field_source, bump_version=True)
            platform_store.append_audit(
                WEB_DATA_DIR,
                kind="quality",
                action="update_profile",
                detail={
                    "profile_id": row["id"],
                    "version": row.get("version"),
                    "max_latency_ms": row.get("proxy_max_latency_ms"),
                    "exclude_countries": row.get("proxy_exclude_countries"),
                    "arp_check_enabled": row.get("proxy_arp_check_enabled"),
                },
            )
        elif "quality_profile_id" in incoming:
            profiles, _ = _ensure_quality_profiles(next_config)
            if requested_profile not in profiles:
                raise ValueError(f"未知质检 profile: {requested_profile}")
            row = profiles[requested_profile]
            next_config["quality_profile_id"] = requested_profile
            for key in QUALITY_FLAT_KEYS:
                if key in row:
                    next_config[key] = row[key]
            platform_store.append_audit(
                WEB_DATA_DIR,
                kind="quality",
                action="activate_profile",
                detail={"profile_id": requested_profile, "version": row.get("version")},
            )

        if "export_quality_profile" in incoming:
            export_id = _profile_id_clean(
                incoming.get("export_quality_profile"),
                next_config.get("quality_profile_id") or "default",
            )
            profiles, _ = _ensure_quality_profiles(next_config)
            if export_id not in profiles:
                raise ValueError(f"未知出口绑定 profile: {export_id}")
            next_config["export_quality_profile"] = export_id
            platform_store.append_audit(
                WEB_DATA_DIR,
                kind="quality",
                action="bind_export_profile",
                detail={"export_quality_profile": export_id},
            )
        elif "export_quality_profile" not in next_config:
            next_config["export_quality_profile"] = next_config.get("quality_profile_id") or "default"

    _atomic_json(CONFIG_FILE, next_config)
    if hasattr(worker, "reload_settings"):
        worker.reload_settings()
    return _public_settings(next_config)


def _pull_api_public(config=None):
    """Effective client-facing pull-API account (same source as settings)."""
    from urllib.parse import urlencode

    cfg = config if isinstance(config, dict) else _read_config()
    settings = _public_settings(cfg)
    base = settings["pull_api_base"]
    user = settings["pull_api_user"]
    password = settings["pull_api_pass"]
    shuliang = settings["pull_api_shuliang"]
    api_id = settings["pull_api_id"]
    scheme = settings["export_proxy_protocol"]
    params = {
        "user": user,
        "pass": password,
        "shuliang": shuliang,
        "id": api_id,
        "scheme": scheme,
    }
    params_masked = dict(params)
    params_masked["pass"] = _mask_secret(password)
    query = urlencode(params)
    query_masked = urlencode(params_masked)
    request_url = f"{base}?{query}" if base else ""
    request_url_masked = f"{base}?{query_masked}" if base else ""
    qcfg = proxy_quality.quality_settings(cfg)
    public_base = ""
    try:
        public_base = _public_base()
    except Exception:
        public_base = ""
    token = ""
    try:
        token = _export_token()
    except Exception:
        token = ""
    export_rule = settings.get("export_quality_profile") or settings.get("quality_profile_id") or "default"
    qualified_query = urlencode({
        "token": token,
        "scheme": scheme,
        "shuliang": shuliang,
        "rule": export_rule,
    }) if token else ""
    qualified_url = f"{public_base}/api/export/qualified-proxies?{qualified_query}" if public_base and token else ""
    configured = bool(base and user)
    local_shortcircuit = configured and _is_local_shortcircuit_base(base)
    if not configured:
        pull_mode = "unconfigured"
    elif local_shortcircuit:
        pull_mode = "local_shortcircuit"
    else:
        pull_mode = "external"
    compat_url_masked = f"{base}?{query_masked}" if base else ""
    return {
        "api": base,
        "user": user,
        "pass": password,
        "pass_masked": _mask_secret(password),
        "shuliang": shuliang,
        "id": api_id,
        "scheme": scheme,
        "query": query,
        "query_masked": query_masked,
        "request_url": request_url,
        "request_url_masked": request_url_masked,
        "compat_url_masked": compat_url_masked,
        "configured": configured,
        "local_shortcircuit": local_shortcircuit,
        "pull_mode": pull_mode,
        "pull_mode_note": (
            "外部上游与本地 8892/api 短路互斥：指向本机 /api 或 :8892 时读账号池，否则 HTTP 拉外部列表。"
        ),
        "quality": {
            "enabled": bool(qcfg["enabled"]),
            "max_latency_ms": int(qcfg["max_latency_ms"]),
            "exclude_countries": list(qcfg["exclude_countries"]),
            "arp_check_enabled": bool(qcfg["arp_check_enabled"]),
            "arp_probe_url": qcfg["arp_probe_url"],
            "arp_publish_url": qcfg["arp_publish_url"],
            "arp_mapping": {
                "ARP4": "sid + ark + bfp + ftr，且 ftr 含 v2_tt（对齐 adobe.DecodePoolARPToken）",
                "publish_200": "ARP 路径探测成功；若配置 arp_publish_url 则需 HTTP 200",
                "latency": f"<= {qcfg['max_latency_ms']} ms",
                "country": f"排除 {','.join(qcfg['exclude_countries'])}",
            },
            "version": int(settings.get("proxy_quality_version") or 0),
            "updated_at": settings.get("proxy_quality_updated_at") or "",
        },
        "qualified_url": qualified_url,
        "qualified_url_note": "客户端请优先用质检后地址；上游 8892 原始列表会经 ARP/延迟/国家过滤后再返回。",
    }


CONFIG = _read_config()
WEB_USERNAME = str(os.environ.get("NODES_WEB_USERNAME") or CONFIG.get("web_username") or "admin")
WEB_PASSWORD_HASH = str(
    os.environ.get("NODES_WEB_PASSWORD_HASH") or CONFIG.get("web_password_hash") or ""
)
WEB_SESSION_SECRET = str(
    os.environ.get("NODES_WEB_SESSION_SECRET") or CONFIG.get("web_session_secret") or ""
)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = WEB_SESSION_SECRET or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=12 * 60 * 60,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

_login_attempts = defaultdict(deque)
_login_lock = threading.Lock()


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _safe_error(error):
    text = str(error).replace("\r", " ").replace("\n", " ")
    return text[:240]


class TaskStore:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.tasks = self._load()
        changed = False
        for task in self.tasks:
            if task.get("status") in {"queued", "running"}:
                task["status"] = "interrupted"
                task["finished_at"] = _utc_now()
                task.setdefault("logs", []).append("Web 服务重启，任务已中断")
                changed = True
        if changed:
            self._save()

    def _load(self):
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, list) else []
        except (OSError, ValueError):
            return []

    def _save(self):
        _atomic_json(self.path, self.tasks[:200])

    def _find(self, task_id):
        return next((item for item in self.tasks if item.get("id") == task_id), None)

    def list(self, limit=50):
        with self.lock:
            return json.loads(json.dumps(self.tasks[:limit]))

    def get(self, task_id):
        with self.lock:
            task = self._find(task_id)
            return json.loads(json.dumps(task)) if task else None

    def active(self):
        with self.lock:
            return next(
                (item for item in self.tasks if item.get("status") in {"queued", "running"}),
                None,
            )

    def start_task(self, count, concurrency):
        with self.lock:
            if self.active():
                raise RuntimeError("已有注册任务在运行")
            task_id = datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)
            task = {
                "id": task_id,
                "status": "queued",
                "requested": count,
                "concurrency": concurrency,
                "completed": 0,
                "successes": 0,
                "partials": 0,
                "failures": 0,
                "proxy_count": 0,
                "created_at": _utc_now(),
                "started_at": None,
                "finished_at": None,
                "account_file": f"accounts_{task_id}.jsonl",
                "proxy_file": f"proxies_{task_id}.txt",
                "logs": [f"任务已创建：{count} 个账号，并发 {concurrency}"],
            }
            self.tasks.insert(0, task)
            self._save()
        thread = threading.Thread(target=self._run, args=(task_id,), daemon=True)
        thread.start()
        return self.get(task_id)

    def _update(self, task_id, **values):
        with self.lock:
            task = self._find(task_id)
            if not task:
                return
            task.update(values)
            self._save()

    def _event(self, task_id, message):
        with self.lock:
            task = self._find(task_id)
            if not task:
                return
            task.setdefault("logs", []).append(message[:300])
            task["logs"] = task["logs"][-100:]
            self._save()

    def _run(self, task_id):
        task = self.get(task_id)
        if not task:
            return
        self._update(task_id, status="running", started_at=_utc_now())
        self._event(task_id, "注册 worker 已启动")
        account_path = str(ACCOUNT_DIR / task["account_file"])
        proxy_path = str(NODE_DIR / task["proxy_file"])

        def execute(index):
            return worker.register_one(index, True, account_path, proxy_path)

        with ThreadPoolExecutor(max_workers=task["concurrency"]) as executor:
            futures = {
                executor.submit(execute, index): index
                for index in range(1, task["requested"] + 1)
            }
            for future in as_completed(futures):
                index = futures[future]
                success = partial = False
                proxies = 0
                try:
                    record = future.result()
                    proxies = int((record or {}).get("proxy_count") or 0)
                    success = proxies > 0
                    partial = bool(record) and not success
                    message = (
                        f"#{index} 完成，导出 {proxies} 个代理"
                        if success
                        else f"#{index} 未完整产出，已保留诊断记录"
                    )
                except Exception as error:
                    message = f"#{index} 失败：{_safe_error(error)}"
                with self.lock:
                    current = self._find(task_id)
                    if not current:
                        return
                    current["completed"] += 1
                    current["successes"] += int(success)
                    current["partials"] += int(partial)
                    current["failures"] += int(not success and not partial)
                    current["proxy_count"] += proxies
                    current.setdefault("logs", []).append(message)
                    self._save()

        final = self.get(task_id)
        if final["successes"] == final["requested"]:
            status = "success"
        elif final["successes"] > 0 or final["partials"] > 0:
            status = "partial"
        else:
            status = "failed"
        self._update(task_id, status=status, finished_at=_utc_now())
        self._event(task_id, f"任务结束：{final['successes']}/{final['requested']} 成功")


TASK_STORE = TaskStore(TASKS_FILE)
_POOL_LOOP_STARTED = False
_POOL_LOOP_LOCK = threading.Lock()


def _is_authenticated():
    return session.get("authenticated") is True and session.get("username") == WEB_USERNAME


def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _too_many_logins(address):
    now = time.monotonic()
    with _login_lock:
        attempts = _login_attempts[address]
        while attempts and attempts[0] < now - 600:
            attempts.popleft()
        return len(attempts) >= 8


def _record_failed_login(address):
    with _login_lock:
        _login_attempts[address].append(time.monotonic())


def _export_token():
    token = str(os.environ.get("NODES_EXPORT_TOKEN") or "").strip()
    if token:
        return token
    config = _read_config()
    token = str(config.get("export_token") or "").strip()
    if token:
        return token
    if app.config.get("TESTING"):
        return "test-export-token"
    token = secrets.token_urlsafe(24)
    next_config = dict(config)
    next_config["export_token"] = token
    _atomic_json(CONFIG_FILE, next_config)
    return token


def _token_matches(supplied, expected):
    left = str(supplied or "")
    right = str(expected or "")
    if not left or not right or len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def _request_export_token_candidates():
    values = []
    header = str(request.headers.get("X-Export-Token") or "").strip()
    if header:
        values.append(header)
    auth = str(request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        values.append(auth[7:].strip())
    query = str(request.args.get("token") or "").strip()
    if query:
        values.append(query)
    view = str((request.view_args or {}).get("export_token") or "").strip()
    if view:
        values.append(view)
    return values


def _request_has_export_token():
    expected = _export_token()
    return any(_token_matches(value, expected) for value in _request_export_token_candidates())


def _can_export_clash():
    return _request_has_export_token() or _is_authenticated()


def _pool_snapshot(probe_missing=False, rule_id=None):
    settings = pool.pool_settings(_read_config())
    raw = _read_config()
    config = _config_for_quality(raw, rule_id=rule_id)
    entries = pool.live_entries(_account_records(), NODE_DIR, settings, time.time())
    qcfg = proxy_quality.quality_settings(config)
    quality_report = {
        "enabled": bool(qcfg["enabled"]),
        "scanned": 0,
        "accepted": 0,
        "rejected": 0,
        "profile_id": config.get("quality_profile_id") or "default",
    }
    if qcfg["enabled"] and entries:
        filtered = []
        scanned = accepted = rejected = skipped = 0
        scheme = _export_protocol_from_config(raw)
        for item in entries:
            hosts, report = proxy_quality.filter_host_list(
                item.get("slots") or [],
                item.get("proxy_username") or "",
                item.get("proxy_password") or "",
                settings=config,
                data_dir=WEB_DATA_DIR,
                scheme=scheme,
                probe_missing=probe_missing,
            )
            scanned += int(report.get("scanned") or 0)
            accepted += int(report.get("accepted") or 0)
            rejected += int(report.get("rejected") or 0)
            skipped += int(report.get("skipped_unprobed") or 0)
            if not hosts:
                continue
            next_item = dict(item)
            next_item["slots"] = hosts
            filtered.append(next_item)
        entries = filtered
        quality_report = {
            "enabled": True,
            "scanned": scanned,
            "accepted": accepted,
            "rejected": rejected,
            "skipped_unprobed": skipped,
            "max_latency_ms": qcfg["max_latency_ms"],
            "exclude_countries": qcfg["exclude_countries"],
            "arp_check_enabled": qcfg["arp_check_enabled"],
            "probe_missing": bool(probe_missing),
            "profile_id": config.get("quality_profile_id") or "default",
        }
    cap = pool.capacity(entries, settings)
    cap["accounts"] = [
        {"email": item["email"], "slots": len(item["slots"])}
        for item in entries
    ]
    cap["quality"] = quality_report
    return settings, entries, cap


def _live_proxy_body(protocol=None):
    _settings, entries, _cap = _pool_snapshot(probe_missing=True)
    scheme = _resolve_export_protocol(protocol)
    lines = pool.format_proxy_lines(entries, worker._format_proxy_url, protocol=scheme)
    return "\n".join(lines) + ("\n" if lines else "")


def _fetch_upstream_pull_proxies(config=None, limit=None):
    cfg = config if isinstance(config, dict) else _read_config()
    settings = _public_settings(cfg)
    base = settings["pull_api_base"]
    user = settings["pull_api_user"]
    password = settings["pull_api_pass"]
    shuliang = settings["pull_api_shuliang"]
    api_id = settings["pull_api_id"]
    if not base or not user:
        raise RuntimeError("未配置拉代理 API（pull_api_base / pull_api_user）")
    count = int(limit) if limit else shuliang
    count = max(1, min(10000, count))

    # Avoid recursive HTTP to this same Nodes /api (8892 historically proxies here).
    base_l = base.lower()
    if _is_local_shortcircuit_base(base_l):
        lines = [proxy_quality.normalize_proxy_url(item) for item in _live_proxy_body().splitlines()]
        lines = [item for item in lines if item]
        start = max(0, (int(api_id) - 1) * count)
        page = lines[start:start + count]
        return page, f"{base}?user={user}&pass=***&shuliang={count}&id={api_id} (local-pool)"

    query = urlencode({
        "user": user,
        "pass": password,
        "shuliang": count,
        "id": api_id,
    })
    # Plain text list URLs (e.g. proxy-checker repo) keep optional query but work either way.
    if "?" in base:
        url = f"{base}&{query}"
    else:
        url = f"{base}?{query}"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    lines = []
    seen = set()
    for raw in response.text.splitlines():
        proxy = proxy_quality.normalize_proxy_url(raw)
        if not proxy or proxy in seen:
            continue
        seen.add(proxy)
        lines.append(proxy)
    if limit is not None:
        lines = lines[:count]
    return lines, url


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "nodes-dashboard"})


@app.get("/api")
def provider_compat_api():
    """Compatibility endpoint for the external proxy-pool URL contract (port 8892)."""
    settings = _public_settings(_read_config())
    expected_user = settings["pull_api_user"] or "lichao"
    expected_pass = settings["pull_api_pass"] or ""
    api_user = str(request.args.get("user") or "").strip()
    api_pass = str(request.args.get("pass") or "").strip()
    if not expected_pass or not _token_matches(api_user, expected_user) or not _token_matches(api_pass, expected_pass):
        return jsonify({"error": "invalid_credentials"}), 401
    try:
        quantity = max(1, min(1000, int(request.args.get("shuliang", settings["pull_api_shuliang"] or 100))))
        provider_id = max(1, int(request.args.get("id", settings["pull_api_id"] or 1)))
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_shuliang_or_id"}), 400
    try:
        protocol = _resolve_export_protocol(
            request.args.get("scheme") or request.args.get("protocol"),
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    lines = _live_proxy_body(protocol=protocol).splitlines()
    if not lines:
        return jsonify({"error": "proxy_pool_empty", "id": provider_id}), 503
    start = (provider_id - 1) * quantity
    page = lines[start:start + quantity]
    body = "\n".join(page) + "\n"
    return Response(body, mimetype="text/plain; charset=utf-8")


def _qualified_pull_body(protocol=None, limit=None, rule_id=None):
    raw = _read_config()
    config = _config_for_quality(raw, rule_id=rule_id)
    scheme = _resolve_export_protocol(protocol)
    upstream, upstream_url = _fetch_upstream_pull_proxies(raw, limit=limit)
    accepted, report = proxy_quality.filter_proxies(
        upstream, settings=config, data_dir=WEB_DATA_DIR,
    )
    rewritten = [proxy_quality.rewrite_scheme(item, scheme) for item in accepted]
    body = "\n".join(rewritten) + ("\n" if rewritten else "")
    return body, {
        "upstream_url_masked": re.sub(r"(pass=)[^&]+", r"\1***", upstream_url),
        "upstream_count": len(upstream),
        "quality": report,
        "scheme": scheme,
        "rule_id": config.get("quality_profile_id") or "default",
    }


def _public_base():
    root = (request.url_root or "").rstrip("/")
    script = (request.script_root or "").rstrip("/")
    if script and (root == script or root.endswith(script)):
        return root
    return root + script


def _subscription_urls():
    token = _export_token()
    public_base = _public_base()
    protocol = _export_protocol_from_config()
    protocol_q = f"&protocol={protocol}" if protocol != "http" else ""
    internal = f"http://127.0.0.1:8891/nodes/api/export/live-proxies?token={token}{protocol_q}"
    public = f"{public_base}/api/export/live-proxies?token={token}{protocol_q}"
    gpt_public = f"{public_base}/api/export/gpt-gateway?token={token}{protocol_q}"
    gpt_internal = f"http://127.0.0.1:8891/nodes/api/export/gpt-gateway?token={token}{protocol_q}"
    clash_public = f"{public_base}/api/export/clash.yml?token={token}{protocol_q}"
    ladder_public = f"{public_base}/api/export/ladder?token={token}{protocol_q}"
    shuliang = _public_settings(_read_config()).get("pull_api_shuliang", 100)
    export_rule = _public_settings(_read_config()).get("export_quality_profile") or "default"
    qualified_q = urlencode({
        "token": token,
        "scheme": protocol,
        "shuliang": shuliang,
        "rule": export_rule,
    })
    qualified_public = f"{public_base}/api/export/qualified-proxies?{qualified_q}" if public_base and token else ""
    return {
        "resin_internal": internal,
        "resin_public": public,
        "gpt_internal": gpt_internal,
        "gpt_public": gpt_public,
        "clash_public": clash_public,
        "ladder_public": ladder_public,
        "qualified_public": qualified_public,
        "export_proxy_protocol": protocol,
        "export_quality_profile": export_rule,
    }


def _detect_outbound_ipv4():
    """Best-effort primary IPv4 used for outbound traffic (non-loopback)."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            ip = str(sock.getsockname()[0] or "").strip()
        finally:
            sock.close()
        if ip and not pool.is_loopback_host(ip):
            return ip
    except Exception:
        pass
    return ""


def _gateway_export_host(settings=None, config=None):
    """Reachable host for Resin/GPT/Clash/ladder subscription lines."""
    cfg = config if isinstance(config, dict) else _read_config()
    pool_cfg = settings if isinstance(settings, dict) else pool.pool_settings(cfg)
    configured = str(pool_cfg.get("gateway_host") or pool.DEFAULT_GATEWAY_HOST).strip() or pool.DEFAULT_GATEWAY_HOST
    public = (
        str(cfg.get("resin_gateway_public_host") or "").strip()
        or str(os.environ.get("NODES_GATEWAY_PUBLIC_HOST") or "").strip()
    )
    host = pool.advertise_gateway_host(configured, public)
    if not pool.is_loopback_host(host):
        return host
    detected = _detect_outbound_ipv4()
    if detected:
        return detected
    return host


def _gpt_gateway_body(settings, live_slots, protocol=None):
    token, auth_version = pool.resin_auth(_read_config())
    if not token:
        return ""
    scheme = _resolve_export_protocol(protocol)
    return "\n".join(pool.gpt_gateway_lines(
        int(live_slots),
        token,
        _gateway_export_host(settings),
        settings["gateway_port"],
        auth_version,
        settings["gateway_platform"],
        protocol=scheme,
    )) + "\n"


def _maybe_fill_capacity(auto_register=True):
    # Probe so shortage is based on quality-admitted slots, not raw hosts.
    settings, _entries, cap = _pool_snapshot(probe_missing=True)
    started = None
    if auto_register and settings["auto_register"] and cap["needed_accounts"] > 0 and not TASK_STORE.active():
        count = min(int(settings["max_register_per_round"]), int(cap["needed_accounts"]))
        started = TASK_STORE.start_task(count, 1)
        cap["register_started"] = started.get("id") if started else None
        cap["register_count"] = count
    else:
        cap["register_started"] = None
        cap["register_count"] = 0
    cap["active_task"] = (TASK_STORE.active() or {}).get("id")
    return cap, started


def _start_pool_loop():
    global _POOL_LOOP_STARTED
    if app.config.get("TESTING") or os.environ.get("NODES_DISABLE_POOL_LOOP") == "1":
        return
    with _POOL_LOOP_LOCK:
        if _POOL_LOOP_STARTED:
            return
        _POOL_LOOP_STARTED = True

    def _loop():
        while True:
            try:
                settings = pool.pool_settings(_read_config())
                time.sleep(int(settings["loop_seconds"]))
                pruned = _prune_expired_accounts()
                if pruned:
                    print(f"[pool] auto-removed {len(pruned)} expired account(s)")
                _maybe_fill_capacity(auto_register=True)
            except Exception:
                time.sleep(30)

    threading.Thread(target=_loop, name="nodes-pool-loop", daemon=True).start()


@app.before_request
def protect_routes():
    _start_pool_loop()
    if request.endpoint in {
        "login",
        "health",
        "static",
        "live_proxies",
        "gpt_gateway",
        "clash_export",
        "ladder_export",
        "qualified_proxies",
        "provider_compat_api",
    }:
        return None
    if "/api/export/clash" in str(request.path or "") or "/api/v1/exports/clash" in str(request.path or ""):
        return None
    if "/api/v1/exports/" in str(request.path or ""):
        return None
    if request.endpoint == "ensure_capacity" and _request_has_export_token():
        return None
    if not _is_authenticated():
        if request.path.startswith("/api/") or request.path.startswith("/export/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect(url_for("login", next=request.path))
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        supplied = request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(supplied, session.get("csrf_token", "")):
            return jsonify({"error": "invalid_csrf"}), 403
    return None


@app.after_request
def secure_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.route("/login", methods=["GET", "POST"])
def login():
    if _is_authenticated():
        return redirect(url_for("index"))
    error = None
    username = ""
    if request.method == "POST":
        address = request.remote_addr or "unknown"
        if _too_many_logins(address):
            error = "尝试过于频繁，请稍后再试"
        else:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            valid = bool(WEB_PASSWORD_HASH) and check_password_hash(WEB_PASSWORD_HASH, password)
            if hmac.compare_digest(username, WEB_USERNAME) and valid:
                session.clear()
                session.permanent = True
                session["authenticated"] = True
                session["username"] = WEB_USERNAME
                _csrf_token()
                return redirect(url_for("index"))
            _record_failed_login(address)
            error = "用户名或密码不正确"
    return render_template("login.html", error=error, username=username)


@app.get("/")
def index():
    return render_template(
        "index.html",
        csrf_token=_csrf_token(),
        username=WEB_USERNAME,
        app_base=request.script_root or "",
    )



@app.get("/api/export/live-proxies")
@app.get("/api/v1/exports/live-proxies")
def live_proxies():
    if not _request_has_export_token():
        return jsonify({"error": "unauthorized"}), 401
    try:
        protocol = _resolve_export_protocol(request.args.get("protocol") or request.args.get("scheme"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    body = _live_proxy_body(protocol=protocol)
    return Response(body, mimetype="text/plain; charset=utf-8")


@app.get("/api/export/qualified-proxies")
@app.get("/api/v1/exports/qualified-proxies")
def qualified_proxies():
    """Pull upstream 8892 API → quality gate → return only admitted proxies.

    Query:
      token (required), scheme/protocol (http|socks5h), shuliang/limit (optional),
      rule/profile (optional quality profile id)
    """
    if not _request_has_export_token():
        return jsonify({"error": "unauthorized"}), 401
    try:
        protocol = _resolve_export_protocol(
            request.args.get("protocol") or request.args.get("scheme"),
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    limit_raw = request.args.get("shuliang") or request.args.get("limit") or ""
    limit = None
    if str(limit_raw).strip():
        try:
            limit = int(limit_raw)
        except (TypeError, ValueError):
            return jsonify({"error": "shuliang/limit 必须是整数"}), 400
    rule_id = request.args.get("rule") or request.args.get("profile") or None
    try:
        body, meta = _qualified_pull_body(protocol=protocol, limit=limit, rule_id=rule_id)
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    except Exception as error:
        return jsonify({"error": _safe_error(error)}), 502
    if request.args.get("meta") in {"1", "true", "yes"}:
        return jsonify({"ok": True, "body": body, **meta})
    response = Response(body, mimetype="text/plain; charset=utf-8")
    response.headers["X-Proxy-Quality-Accepted"] = str(meta.get("quality", {}).get("accepted") or 0)
    response.headers["X-Proxy-Quality-Rejected"] = str(meta.get("quality", {}).get("rejected") or 0)
    response.headers["X-Proxy-Upstream-Count"] = str(meta.get("upstream_count") or 0)
    response.headers["X-Proxy-Quality-Rule"] = str(meta.get("rule_id") or "")
    return response


@app.get("/api/export/gpt-gateway")
@app.get("/api/v1/exports/gpt-gateway")
def gpt_gateway():
    if not _request_has_export_token():
        return jsonify({"error": "unauthorized"}), 401
    try:
        protocol = _resolve_export_protocol(request.args.get("protocol") or request.args.get("scheme"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    # Cache-based quality snapshot is enough for gateway slot count; avoid blocking probes.
    settings, _entries, cap = _pool_snapshot(probe_missing=False)
    body = _gpt_gateway_body(settings, cap["live_slots"], protocol=protocol)
    if not body.strip():
        # Ship direct live lines when Resin token/slots unavailable but pool has proxies.
        body = _live_proxy_body(protocol=protocol)
        if not body.strip():
            return jsonify({"error": "no_proxies_available"}), 503
    return Response(body, mimetype="text/plain; charset=utf-8")


def _clash_body(settings, live_slots, protocol=None):
    token, auth_version = pool.resin_auth(_read_config())
    if not token:
        return ""
    scheme = _resolve_export_protocol(protocol)
    return pool.clash_yaml(
        int(live_slots),
        token,
        _gateway_export_host(settings),
        settings["gateway_port"],
        auth_version,
        settings["gateway_platform"],
        protocol=scheme,
    )


def _ladder_body(settings, live_slots, protocol=None):
    token, auth_version = pool.resin_auth(_read_config())
    if not token:
        return ""
    scheme = _resolve_export_protocol(protocol)
    return pool.ladder_base64(
        int(live_slots),
        token,
        _gateway_export_host(settings),
        settings["gateway_port"],
        auth_version,
        settings["gateway_platform"],
        protocol=scheme,
    )


@app.get("/api/export/clash.yml")
@app.get("/api/export/clash")
@app.get("/api/export/clash.yml/<export_token>")
@app.get("/api/export/clash/<export_token>")
@app.get("/api/v1/exports/clash.yml")
@app.get("/api/v1/exports/clash")
@app.get("/api/v1/exports/clash.yml/<export_token>")
@app.get("/api/v1/exports/clash/<export_token>")
def clash_export(export_token=None):
    if not _can_export_clash():
        return jsonify({"error": "unauthorized"}), 401
    try:
        protocol = _resolve_export_protocol(request.args.get("protocol") or request.args.get("scheme"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    settings, _entries, cap = _pool_snapshot(probe_missing=True)
    body = _clash_body(settings, cap["live_slots"], protocol=protocol)
    if not body.strip():
        return jsonify({"error": "resin_proxy_token_missing"}), 503
    response = Response(body, mimetype="text/yaml; charset=utf-8")
    response.headers["Content-Disposition"] = 'attachment; filename="clash.yml"'
    response.headers["Profile-Update-Interval"] = "1"
    response.headers["Subscription-Userinfo"] = (
        f"upload=0; download=0; total=0; expire={int(time.time()) + 7 * 86400}"
    )
    return response


@app.get("/api/export/ladder")
@app.get("/api/v1/exports/ladder")
def ladder_export():
    if not _request_has_export_token():
        return jsonify({"error": "unauthorized"}), 401
    try:
        protocol = _resolve_export_protocol(request.args.get("protocol") or request.args.get("scheme"))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    settings, _entries, cap = _pool_snapshot(probe_missing=True)
    body = _ladder_body(settings, cap["live_slots"], protocol=protocol)
    if not body.strip():
        return jsonify({"error": "resin_proxy_token_missing"}), 503
    return Response(body, mimetype="text/plain; charset=utf-8")


@app.get("/api/pool")
def pool_status():
    return jsonify({"pool": _pool_public()})


@app.post("/api/pool/ensure-capacity")
def ensure_capacity():
    payload = request.get_json(silent=True) or {}
    auto_register = True if "auto_register" not in payload else bool(payload.get("auto_register"))
    # Re-probe pool slots so capacity/export only keep ARP/latency/country passers.
    try:
        _pool_snapshot(probe_missing=True)
    except Exception:
        pass
    try:
        cap, started = _maybe_fill_capacity(auto_register=auto_register)
    except RuntimeError as error:
        return jsonify({"error": str(error), "pool": _pool_public()}), 409
    return jsonify({
        "ok": True,
        "pool": _pool_public(),
        "capacity": cap,
        "task": started,
        "inventory": _quality_inventory(persist=True),
    })


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


def _deleted_emails_file():
    return ACCOUNT_DIR / "deleted_emails.json"


def _load_deleted_emails():
    try:
        value = json.loads(_deleted_emails_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(value, list):
        return {str(item).strip().lower() for item in value if str(item).strip()}
    return set()


def _save_deleted_emails(emails):
    unique = sorted({str(item).strip().lower() for item in emails if str(item).strip()})
    _atomic_json(_deleted_emails_file(), unique)


def _record_stamp(record):
    for key in ("updated_at", "imported_at", "usage_synced_at", "ts"):
        try:
            value = int(record.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value:
            return value
    return 0


def _account_records():
    deleted = _load_deleted_emails()
    latest = {}
    for path in sorted(ACCOUNT_DIR.glob("*.jsonl")):
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    email = str(record.get("email") or "").strip()
                    key = email.lower()
                    if not email or key in deleted:
                        continue
                    previous = latest.get(key)
                    if previous is None or _record_stamp(record) >= _record_stamp(previous):
                        latest[key] = record
        except OSError:
            continue
    return list(latest.values())


def _proxy_files():
    files = []
    for path in sorted(NODE_DIR.glob("*.txt"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                count = sum(1 for line in handle if line.strip())
            stat = path.stat()
            files.append({
                "name": path.name,
                "count": count,
                "size": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            })
        except OSError:
            continue
    return files


def _public_accounts(records, full=False):
    result = []
    for record in sorted(records, key=lambda item: int(item.get("ts") or 0), reverse=True):
        result.append(_serialize_account(record, full=full))
    return result


def _account_map():
    latest = {}
    for record in _account_records():
        email = str(record.get("email") or "").strip().lower()
        if email:
            latest[email] = record
    return latest


def _find_account(email):
    return _account_map().get(str(email or "").strip().lower())


def _iso_from_unix(value):
    try:
        stamp = int(value)
    except (TypeError, ValueError):
        return None
    if stamp <= 0:
        return None
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def _api_key_blob(record):
    blob = record.get("api_key")
    return dict(blob) if isinstance(blob, dict) else {}


def _account_api_urls(record):
    account_id = str(record.get("account_id") or "").strip()
    api_key = _api_key_blob(record)
    token = str(api_key.get("token") or record.get("api_token") or "").strip()
    user = str(record.get("proxy_username") or "").strip()
    password = str(record.get("proxy_password") or "").strip()
    protocol = _export_protocol_from_config()
    api_protocol = worker.proxyscrape_protocol_param(protocol)
    public_list = ""
    dashboard_list = ""
    dashboard_overview = ""
    if account_id:
        public_list = (
            f"{worker.PS_PUBLIC_API}/v4/account/{account_id}/datacenter_shared/proxy-list"
            f"?protocol={api_protocol}&format=credentials&credential_format=3"
        )
        dashboard_list = (
            f"{worker.PS_BASE}/v2/v4/account/{account_id}/datacenter_shared/proxy-list"
            f"?protocol={api_protocol}&format=normal"
        )
        dashboard_overview = f"{worker.PS_BASE}/v2/v4/account/{account_id}/services/overview"
    return {
        "public_base": worker.PS_PUBLIC_API,
        "public_proxy_list": public_list,
        "dashboard_overview": dashboard_overview,
        "dashboard_proxy_list": dashboard_list,
        "api_token_header": "api-token",
        "dashboard_auth_header": "Authorization: Bearer <access_token>",
        "proxy_credential": f"{user}:{password}" if user and password else "",
        "proxy_protocol": protocol,
        "proxy_url_template": f"{protocol}://{user}:{password}@HOST:PORT" if user and password else "",
        "curl_public_proxy_list": (
            f"curl -H \"api-token: {token}\" \"{public_list}\"" if token and public_list else ""
        ),
        "has_token": bool(token),
    }


def _usage_fields(record):
    summary = record.get("account_summary") if isinstance(record.get("account_summary"), dict) else {}
    expiry = record.get("expiration_time") or record.get("expiry") or summary.get("expiry")
    try:
        expiry = int(expiry) if expiry else None
    except (TypeError, ValueError):
        expiry = None
    total = record.get("bandwidth_total")
    if total is None:
        total = record.get("bandwidth")
    if total is None:
        total = summary.get("bandwidth_total")
    used = record.get("bandwidth_used")
    if used is None:
        used = summary.get("bandwidth_used")
    try:
        total = int(total) if total is not None else None
    except (TypeError, ValueError):
        total = None
    try:
        used = int(used) if used is not None else None
    except (TypeError, ValueError):
        used = None
    remaining = record.get("bandwidth_remaining")
    if remaining is None and total is not None and used is not None:
        remaining = max(0, total - used)
    try:
        remaining = int(remaining) if remaining is not None else None
    except (TypeError, ValueError):
        remaining = None
    days = record.get("days_remaining")
    if days is None:
        days = summary.get("days_remaining")
    if days is None and expiry:
        days = max(0, int((expiry - time.time()) // 86400))
    try:
        days = int(days) if days is not None else None
    except (TypeError, ValueError):
        days = None
    return {
        "expires_at": _iso_from_unix(expiry),
        "expiry": expiry,
        "days_remaining": days,
        "expired": bool(expiry and expiry <= time.time()),
        "bandwidth_total": total,
        "bandwidth_used": used if used is not None else (0 if total is not None else None),
        "bandwidth_remaining": remaining,
        "usage_synced_at": _iso_from_unix(record.get("usage_synced_at")),
        "plan_status": summary.get("status") or record.get("plan_status") or "",
    }


def _serialize_account(record, full=False):
    api_key = _api_key_blob(record)
    token = str(api_key.get("token") or record.get("api_token") or "").strip()
    item = {
        "email": record.get("email") or "",
        "verified": bool(record.get("verified")),
        "trial_claimed": bool(record.get("trial_claimed")),
        "proxy_count": int(record.get("proxy_count") or 0),
        "account_id": record.get("account_id") or "",
        "has_api_key": bool(token),
        "has_proxy_credentials": bool(record.get("proxy_username")),
        "is_trial": record.get("is_trial"),
        "created_at": _iso_from_unix(record.get("ts")),
    }
    item.update(_usage_fields(record))
    if not full:
        return item
    item.update({
        "password": record.get("password") or "",
        "access_token": record.get("access_token") or "",
        "proxy_username": record.get("proxy_username") or "",
        "proxy_password": record.get("proxy_password") or "",
        "account_key": record.get("account_key") or "",
        "api_token": token,
        "api_key_id": api_key.get("id") or record.get("api_key_id") or "",
        "api_key_name": api_key.get("name") or record.get("api_key_name") or worker.API_KEY_NAME,
        "permissions": api_key.get("permissions") or record.get("permissions") or [],
        "allowed_subaccounts": api_key.get("allowed_subaccounts") or record.get("allowed_subaccounts") or [],
        "allowed_ips": api_key.get("allowed_ips") or record.get("allowed_ips") or [],
        "proxy_credentials_enabled": record.get("proxy_credentials_enabled"),
        "max_connections": record.get("max_connections"),
        "proxy_amount": record.get("proxy_amount"),
        "notes": record.get("notes") or "",
        "userData": record.get("userData") or {},
        "account_summary": record.get("account_summary"),
        "api": _account_api_urls(record),
        "permission_catalog": worker.PERMISSION_CATALOG,
    })
    return item


def _pool_public():
    settings, _entries, cap = _pool_snapshot()
    urls = _subscription_urls()
    resin_token, auth_version = pool.resin_auth(_read_config())
    export_host = _gateway_export_host(settings)
    if resin_token:
        user, password = pool.gateway_identity(
            1, auth_version, settings["gateway_platform"], resin_token,
        )
        gateway_sample = (
            f"http://{user}:{password}@{export_host}:{settings['gateway_port']}"
        )
    else:
        gateway_sample = (
            f"http://{settings['gateway_platform']}.n01:<RESIN_PROXY_TOKEN>"
            f"@{export_host}:{settings['gateway_port']}"
        )
    return {
        **cap,
        "subscription_url": urls["resin_internal"],
        "subscription_url_public": urls["resin_public"],
        "gpt_subscription_url": urls["gpt_public"],
        "clash_subscription_url": urls["clash_public"],
        "ladder_subscription_url": urls["ladder_public"],
        "qualified_subscription_url": urls["qualified_public"],
        "qualified_url": urls["qualified_public"],
        "export_proxy_protocol": urls["export_proxy_protocol"],
        "gpt_gateway_sample": gateway_sample,
        "gpt_gateway_host": f"{export_host}:{settings['gateway_port']}",
        "auth_version": auth_version,
        "has_resin_token": bool(resin_token),
    }


def _save_account_record(record):
    email = str(record.get("email") or "").strip().lower()
    if email:
        deleted = _load_deleted_emails()
        if email in deleted:
            deleted.discard(email)
            _save_deleted_emails(deleted)
    path = ACCOUNT_DIR / "accounts_edits.jsonl"
    worker.save_account(record, str(path))
    return record


def _normalize_email_list(values):
    result = []
    seen = set()
    for item in values or []:
        email = str(item or "").strip()
        key = email.lower()
        if not email or key in seen:
            continue
        seen.add(key)
        result.append(email)
    return result


def _delete_accounts(emails):
    wanted = {item.lower() for item in _normalize_email_list(emails)}
    if not wanted:
        raise ValueError("没有要删除的账号")
    existing = _account_map()
    removed = [existing[key].get("email") or key for key in wanted if key in existing]
    if not removed:
        return []
    deleted = _load_deleted_emails()
    deleted.update(item.lower() for item in removed)
    _save_deleted_emails(deleted)
    return removed


def _account_expiry_unix(record):
    usage = _usage_fields(record)
    expiry = usage.get("expiry")
    try:
        return int(expiry) if expiry else None
    except (TypeError, ValueError):
        return None


def _prune_expired_accounts(now=None):
    """Keep only valid accounts: auto-delete rows whose plan/token expiry has passed."""
    stamp = int(now if now is not None else time.time())
    expired_emails = []
    for record in _account_records():
        expiry = _account_expiry_unix(record)
        if expiry and expiry <= stamp:
            email = str(record.get("email") or "").strip()
            if email:
                expired_emails.append(email)
    if not expired_emails:
        return []
    try:
        return _delete_accounts(expired_emails)
    except ValueError:
        return []


def _parse_account_text(text):
    payload = str(text or "").strip()
    if not payload:
        return []
    try:
        data = json.loads(payload)
    except ValueError:
        data = None
    if isinstance(data, dict):
        if isinstance(data.get("accounts"), list):
            return data["accounts"]
        return [data]
    if isinstance(data, list):
        return data
    items = []
    for index, line in enumerate(payload.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError as error:
            raise ValueError(f"第 {index} 行不是 JSON") from error
        items.append(item)
    return items


def _normalize_imported_record(raw):
    if not isinstance(raw, dict):
        raise ValueError("账号必须是 JSON 对象")
    email = str(raw.get("email") or "").strip()
    if "@" not in email:
        raise ValueError("缺少有效邮箱")
    record = dict(raw)
    record["email"] = email
    if record.get("api_token") and not isinstance(record.get("api_key"), dict):
        record["api_key"] = {
            "token": str(record.get("api_token") or "").strip(),
            "id": str(record.get("api_key_id") or "").strip(),
            "name": str(record.get("api_key_name") or worker.API_KEY_NAME).strip() or worker.API_KEY_NAME,
            "permissions": record.get("permissions") or [],
            "allowed_subaccounts": record.get("allowed_subaccounts") or [],
            "allowed_ips": record.get("allowed_ips") or [],
        }
    try:
        record["proxy_count"] = int(record.get("proxy_count") or 0)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{email} 的代理数无效") from error
    record["verified"] = _as_bool(record.get("verified"))
    record["trial_claimed"] = _as_bool(record.get("trial_claimed"))
    record["ts"] = int(record.get("ts") or time.time())
    record["imported_at"] = int(time.time())
    return record


def _import_accounts(items):
    if not isinstance(items, list) or not items:
        raise ValueError("没有可导入的账号")
    if len(items) > 500:
        raise ValueError("单次最多导入 500 个账号")
    imported = []
    restored = []
    deleted = _load_deleted_emails()
    changed_deleted = False
    for raw in items:
        record = _normalize_imported_record(raw)
        email_key = record["email"].lower()
        existing = _find_account(record["email"])
        if existing:
            merged = dict(existing)
            merged.update(record)
            record = merged
        elif email_key in deleted:
            deleted.discard(email_key)
            changed_deleted = True
            restored.append(record["email"])
        _save_account_record(record)
        imported.append(record["email"])
    if changed_deleted:
        _save_deleted_emails(deleted)
    return {"imported": imported, "restored": restored}


def _apply_account_update(record, payload):
    data = payload if isinstance(payload, dict) else {}
    next_record = dict(record)
    text_fields = (
        "password", "access_token", "account_id", "proxy_username", "proxy_password",
        "account_key", "notes",
    )
    for key in text_fields:
        if key in data:
            next_record[key] = str(data.get(key) or "").strip()
    if "proxy_count" in data:
        try:
            next_record["proxy_count"] = int(data.get("proxy_count") or 0)
        except (TypeError, ValueError) as error:
            raise ValueError("代理数必须是整数") from error
    if "verified" in data:
        next_record["verified"] = _as_bool(data.get("verified"))
    if "trial_claimed" in data:
        next_record["trial_claimed"] = _as_bool(data.get("trial_claimed"))
    api_key = _api_key_blob(next_record)
    if "api_token" in data:
        api_key["token"] = str(data.get("api_token") or "").strip()
    if "api_key_id" in data:
        api_key["id"] = str(data.get("api_key_id") or "").strip()
    if "api_key_name" in data:
        api_key["name"] = str(data.get("api_key_name") or "").strip() or worker.API_KEY_NAME
    if "permissions" in data:
        raw = data.get("permissions") or []
        if not isinstance(raw, list):
            raise ValueError("权限必须是数组")
        api_key["permissions"] = [str(item).strip() for item in raw if str(item).strip()]
    if "allowed_subaccounts" in data:
        raw = data.get("allowed_subaccounts") or []
        if not isinstance(raw, list):
            raise ValueError("allowed_subaccounts 必须是数组")
        api_key["allowed_subaccounts"] = [str(item).strip() for item in raw if str(item).strip()]
    if "allowed_ips" in data:
        raw = data.get("allowed_ips") or []
        if not isinstance(raw, list):
            raise ValueError("allowed_ips 必须是数组")
        api_key["allowed_ips"] = [str(item).strip() for item in raw if str(item).strip()]
    if api_key:
        next_record["api_key"] = api_key
    next_record["ts"] = int(record.get("ts") or time.time())
    next_record["updated_at"] = int(time.time())
    return next_record


def _ps_session():
    session_obj = requests.Session()
    session_obj.headers.update(worker.HEADERS)
    return session_obj


def _refresh_account_remote(record, create_key=False, permissions=None):
    access_token = str(record.get("access_token") or "").strip()
    account_id = str(record.get("account_id") or "").strip()
    if not access_token:
        raise RuntimeError("账号没有 access_token，无法向 ProxyScrape 拉数据")
    if not account_id:
        raise RuntimeError("账号没有 account_id，无法向 ProxyScrape 拉数据")
    next_record = dict(record)
    overview = worker.fetch_service_overview(access_token, account_id)
    next_record.update(worker.overview_credentials(overview))
    client = _ps_session()
    try:
        summary = worker.fetch_accounts_summary(client, access_token)
        next_record["account_summary"] = next(
            (item for item in summary if item.get("id") == account_id),
            summary[0] if summary else None,
        )
    except Exception as error:
        next_record["account_summary_error"] = str(error)[:240]
    summary = next_record.get("account_summary") if isinstance(next_record.get("account_summary"), dict) else {}
    if summary.get("expiry") and not next_record.get("expiration_time"):
        next_record["expiration_time"] = summary.get("expiry")
    if summary.get("days_remaining") is not None:
        next_record["days_remaining"] = summary.get("days_remaining")
    if summary.get("status"):
        next_record["plan_status"] = summary.get("status")
    next_record["usage_synced_at"] = int(time.time())
    try:
        plist = worker.list_proxy_hosts(
            access_token, account_id, protocol=_export_protocol_from_config(),
        )
        if plist:
            next_record["proxy_ips"] = plist
            next_record["proxy_count"] = len(plist)
    except Exception as error:
        next_record["proxy_list_error"] = str(error)[:240]
    if create_key:
        perms = permissions if permissions is not None else (
            _api_key_blob(next_record).get("permissions") or list(worker.DEFAULT_API_PERMISSIONS)
        )
        if not perms:
            raise ValueError("至少勾选一项 API 权限")
        next_record["api_key"] = worker.provision_api_key(
            client, access_token, account_id,
            permissions=perms,
            name=_api_key_blob(next_record).get("name") or worker.API_KEY_NAME,
            existing=_api_key_blob(next_record),
        )
    next_record["updated_at"] = int(time.time())
    return next_record


def _quality_inventory(config=None, persist=False):
    """Summarize quality cache + last pool quality report for dashboard."""
    raw = config if isinstance(config, dict) else _read_config()
    cfg = _config_for_quality(raw)
    qcfg = proxy_quality.quality_settings(cfg)
    cache = proxy_quality.load_cache(WEB_DATA_DIR)
    accepted = rejected = 0
    reasons = {}
    for item in (cache or {}).values():
        if not isinstance(item, dict):
            continue
        if item.get("ok"):
            accepted += 1
            continue
        rejected += 1
        reason = str(item.get("reason") or "unknown").strip() or "unknown"
        reasons[reason] = reasons.get(reason, 0) + 1
    try:
        _settings, _entries, cap = _pool_snapshot(probe_missing=False)
        pool_q = cap.get("quality") if isinstance(cap, dict) else {}
    except Exception:
        pool_q = {}
    if isinstance(pool_q, dict) and pool_q.get("enabled") and int(pool_q.get("scanned") or 0) > 0:
        scanned = int(pool_q.get("scanned") or 0)
        pool_accepted = int(pool_q.get("accepted") or 0)
        pool_rejected = int(pool_q.get("rejected") or 0)
    else:
        scanned = accepted + rejected
        pool_accepted = accepted
        pool_rejected = rejected
    ranked = sorted(reasons.items(), key=lambda pair: (-pair[1], pair[0]))[:12]
    public = _public_settings(raw)
    inventory = {
        "enabled": bool(qcfg["enabled"]),
        "scanned": scanned,
        "accepted": pool_accepted,
        "rejected": pool_rejected,
        "cache_accepted": accepted,
        "cache_rejected": rejected,
        "reasons": [{"reason": reason, "count": count} for reason, count in ranked],
        "reject_reasons": {reason: count for reason, count in ranked},
        "source": "pool+cache",
        "max_latency_ms": int(qcfg["max_latency_ms"]),
        "exclude_countries": list(qcfg["exclude_countries"]),
        "arp_check_enabled": bool(qcfg["arp_check_enabled"]),
        "version": int(public.get("proxy_quality_version") or 0),
        "updated_at": public.get("proxy_quality_updated_at") or "",
        "profile_id": public.get("quality_profile_id") or "default",
        "export_profile_id": public.get("export_quality_profile") or "default",
    }
    if persist:
        platform_store.save_inventory_snapshot(WEB_DATA_DIR, inventory)
    return inventory


@app.get("/api/dashboard")
def dashboard():
    records = _account_records()
    files = _proxy_files()
    active = TASK_STORE.active()
    config = _read_config()
    inventory = _quality_inventory(config, persist=True)
    history = platform_store.load_inventory_history(WEB_DATA_DIR, limit=24)
    return jsonify({
        "summary": {
            "accounts": len(records),
            "verified": sum(1 for item in records if item.get("verified")),
            "proxies": sum(item["count"] for item in files),
            "successful_accounts": sum(1 for item in records if int(item.get("proxy_count") or 0) > 0),
            "qualified": inventory.get("accepted"),
            "rejected": inventory.get("rejected"),
        },
        "chain": {
            "captcha": str(config.get("captcha_provider") or worker.CAPTCHA_PROVIDER),
            "mail": str(config.get("mail_provider") or worker.MAIL_PROVIDER),
            "proxy": "enabled" if _as_bool(config.get("proxy_enabled")) else ("configured" if files else "waiting"),
            "output": "enabled",
        },
        "active_task": active.get("id") if active else None,
        "tasks": TASK_STORE.list(8),
        "pool": _pool_public(),
        "pull_api": _pull_api_public(config),
        "inventory": inventory,
        "inventory_history": history,
        "quality_profiles": _profiles_public(config),
        "quality_meta": {
            "version": inventory.get("version"),
            "updated_at": inventory.get("updated_at"),
            "proxy_quality_version": inventory.get("version"),
            "proxy_quality_updated_at": inventory.get("updated_at"),
            "profile_id": inventory.get("profile_id"),
            "export_profile_id": inventory.get("export_profile_id"),
        },
    })


@app.get("/api/accounts")
def accounts():
    pruned = _prune_expired_accounts()
    return jsonify({
        "accounts": _public_accounts(_account_records())[:500],
        "pruned_expired": pruned,
    })


@app.get("/api/permission-catalog")
def permission_catalog():
    return jsonify(worker.PERMISSION_CATALOG)


@app.post("/api/accounts/import")
def import_accounts():
    payload = request.get_json(silent=True) or {}
    try:
        if isinstance(payload.get("accounts"), list):
            items = payload["accounts"]
        else:
            items = _parse_account_text(payload.get("text") or "")
        result = _import_accounts(items)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    return jsonify({
        "ok": True,
        "imported": len(result["imported"]),
        "restored": len(result["restored"]),
        "emails": result["imported"],
        "accounts": _public_accounts(_account_records())[:500],
    })


@app.post("/api/accounts/delete")
def delete_accounts():
    payload = request.get_json(silent=True) or {}
    emails = payload.get("emails") if isinstance(payload.get("emails"), list) else []
    if payload.get("email"):
        emails = list(emails) + [payload.get("email")]
    try:
        removed = _delete_accounts(emails)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    if not removed:
        return jsonify({"error": "没有找到要删除的账号"}), 404
    return jsonify({"ok": True, "deleted": removed, "accounts": _public_accounts(_account_records())[:500]})


@app.post("/api/accounts/sync-usage")
def sync_accounts_usage():
    payload = request.get_json(silent=True) or {}
    emails = _normalize_email_list(payload.get("emails") or [])
    records = _account_records()
    if emails:
        wanted = {item.lower() for item in emails}
        records = [item for item in records if str(item.get("email") or "").lower() in wanted]
    synced = []
    failed = []
    for record in records:
        email = record.get("email") or ""
        if not record.get("access_token") or not record.get("account_id"):
            failed.append({"email": email, "error": "缺少 access_token 或 account_id"})
            continue
        try:
            updated = _refresh_account_remote(record, create_key=False)
            _save_account_record(updated)
            synced.append(email)
        except Exception as error:
            failed.append({"email": email, "error": _safe_error(error)})
    pruned = _prune_expired_accounts()
    return jsonify({
        "ok": True,
        "synced": synced,
        "failed": failed,
        "pruned_expired": pruned,
        "accounts": _public_accounts(_account_records())[:500],
    })


@app.get("/api/accounts/<path:email>")
def account_detail(email):
    record = _find_account(email)
    if not record:
        abort(404)
    return jsonify({"account": _serialize_account(record, full=True)})


@app.delete("/api/accounts/<path:email>")
def delete_account(email):
    try:
        removed = _delete_accounts([email])
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    if not removed:
        abort(404)
    return jsonify({"ok": True, "deleted": removed})


@app.put("/api/accounts/<path:email>")
def update_account(email):
    record = _find_account(email)
    if not record:
        abort(404)
    payload = request.get_json(silent=True) or {}
    try:
        next_record = _apply_account_update(record, payload)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    _save_account_record(next_record)
    return jsonify({"ok": True, "account": _serialize_account(next_record, full=True)})


@app.post("/api/accounts/<path:email>/refresh")
def refresh_account(email):
    record = _find_account(email)
    if not record:
        abort(404)
    try:
        next_record = _refresh_account_remote(record, create_key=False)
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    except Exception as error:
        return jsonify({"error": _safe_error(error)}), 502
    _save_account_record(next_record)
    return jsonify({"ok": True, "account": _serialize_account(next_record, full=True)})


@app.post("/api/accounts/<path:email>/api-key")
def sync_account_api_key(email):
    record = _find_account(email)
    if not record:
        abort(404)
    payload = request.get_json(silent=True) or {}
    try:
        staged = _apply_account_update(record, payload)
        permissions = staged.get("api_key", {}).get("permissions") if isinstance(staged.get("api_key"), dict) else None
        next_record = _refresh_account_remote(staged, create_key=True, permissions=permissions)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    except Exception as error:
        return jsonify({"error": _safe_error(error)}), 502
    _save_account_record(next_record)
    return jsonify({"ok": True, "account": _serialize_account(next_record, full=True)})


@app.get("/api/exports")
def exports():
    account_files = []
    for path in sorted(ACCOUNT_DIR.glob("*.jsonl"), key=lambda item: item.stat().st_mtime, reverse=True):
        stat = path.stat()
        account_files.append({
            "name": path.name,
            "size": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })
    return jsonify({"accounts": account_files, "proxies": _proxy_files()})


@app.get("/api/tasks")
def tasks():
    return jsonify({"tasks": TASK_STORE.list(100)})


@app.post("/api/tasks")
def create_task():
    payload = request.get_json(silent=True) or {}
    try:
        count = int(payload.get("count", 1))
        concurrency = int(payload.get("concurrency", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "注册数量和并发数必须为整数"}), 400
    if not 1 <= count <= 100:
        return jsonify({"error": "注册数量必须在 1-100 之间"}), 400
    if not 1 <= concurrency <= min(8, count):
        return jsonify({"error": "并发数必须在 1-8 之间，且不能超过注册数量"}), 400
    try:
        task = TASK_STORE.start_task(count, concurrency)
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    return jsonify({"task": task}), 202


@app.get("/api/tasks/<task_id>")
def task_detail(task_id):
    task = TASK_STORE.get(task_id)
    if not task:
        abort(404)
    return jsonify({"task": task})


@app.get("/api/settings")
def get_settings():
    config = _read_config()
    group = str(request.args.get("group") or "").strip().lower()
    public = _public_settings(config)
    if group:
        try:
            settings = _settings_for_group(config, group)
        except ValueError as error:
            return jsonify({"error": str(error)}), 400
        payload = {
            "group": group,
            "settings": settings,
            "groups": list(SETTINGS_GROUPS.keys()),
        }
        if group == "sources":
            payload["pull_api"] = _pull_api_public(config)
        if group == "quality":
            payload["quality_meta"] = {
                "proxy_quality_version": public.get("proxy_quality_version"),
                "proxy_quality_updated_at": public.get("proxy_quality_updated_at"),
            }
            payload["quality_profiles"] = _profiles_public(config)
        return jsonify(payload)
    return jsonify({
        "settings": public,
        "groups": {name: list(keys) for name, keys in SETTINGS_GROUPS.items()},
        "pull_api": _pull_api_public(config),
        "quality_profiles": _profiles_public(config),
    })


@app.put("/api/settings")
def put_settings():
    payload = request.get_json(silent=True) or {}
    try:
        settings = _apply_settings(payload)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    group = str(payload.get("group") or "").strip().lower()
    response = {"ok": True, "settings": settings, "groups": list(SETTINGS_GROUPS.keys())}
    if group:
        response["group"] = group
        response["all_settings"] = settings
        response["settings"] = settings
    response["pull_api"] = _pull_api_public()
    response["quality_profiles"] = _profiles_public(_read_config())
    if group == "quality" or (set(payload) & set(QUALITY_FLAT_KEYS)):
        _quality_inventory(persist=True)
    return jsonify(response)


@app.post("/api/quality/dry-run")
def quality_dry_run():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text") or payload.get("proxies") or ""
    if isinstance(text, list):
        lines = [str(item).strip() for item in text if str(item).strip()]
    else:
        lines = [line.strip() for line in str(text).splitlines() if line.strip()]
    try:
        limit = int(payload.get("limit") or 50)
    except (TypeError, ValueError):
        return jsonify({"error": "limit 必须是整数"}), 400
    limit = max(1, min(50, limit))
    lines = lines[:limit]
    if not lines:
        return jsonify({"error": "请粘贴至少一条代理"}), 400
    rule_id = payload.get("rule") or payload.get("profile") or payload.get("quality_profile_id")
    config = _config_for_quality(_read_config(), rule_id=rule_id)
    accepted, report = proxy_quality.filter_proxies(
        lines, settings=config, data_dir=WEB_DATA_DIR, use_cache=False, probe_missing=True,
    )
    return jsonify({
        "ok": True,
        "accepted": accepted,
        "report": report,
        "rule_id": config.get("quality_profile_id") or "default",
        "quality_meta": {
            "proxy_quality_version": _public_settings(_read_config()).get("proxy_quality_version"),
            "proxy_quality_updated_at": _public_settings(_read_config()).get("proxy_quality_updated_at"),
        },
    })


@app.get("/api/quality/profiles")
def quality_profiles_list():
    return jsonify({"ok": True, **_profiles_public(_read_config())})


@app.post("/api/quality/profiles/activate")
def quality_profiles_activate():
    payload = request.get_json(silent=True) or {}
    profile_id = _profile_id_clean(payload.get("id") or payload.get("profile_id"), "")
    if not profile_id:
        return jsonify({"error": "缺少 profile id"}), 400
    try:
        settings = _apply_settings({"group": "quality", "quality_profile_id": profile_id})
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    return jsonify({"ok": True, "settings": settings, "quality_profiles": _profiles_public(_read_config())})


@app.put("/api/quality/profiles/<profile_id>")
def quality_profiles_upsert(profile_id):
    payload = request.get_json(silent=True) or {}
    pid = _profile_id_clean(profile_id, "")
    if not pid:
        return jsonify({"error": "无效 profile id"}), 400
    body = {"group": "quality", "quality_profile_id": pid}
    for key in QUALITY_FLAT_KEYS:
        if key in payload:
            body[key] = payload[key]
    if "name" in payload:
        # name stored via apply through fields dict — pass into apply by writing after
        pass
    if not (set(body) & set(QUALITY_FLAT_KEYS)):
        # activate / rename only
        current = _read_config()
        profiles, _ = _ensure_quality_profiles(current)
        if pid not in profiles and pid not in BUILTIN_QUALITY_PROFILES:
            # create from default flat keys
            for key in QUALITY_FLAT_KEYS:
                body[key] = _public_settings(current).get(key)
        else:
            body["quality_profile_id"] = pid
    try:
        if TASK_STORE.active():
            raise RuntimeError("有注册任务正在运行，请结束后再改配置")
        if set(body) & set(QUALITY_FLAT_KEYS):
            settings = _apply_settings(body)
        else:
            settings = _apply_settings({"group": "quality", "quality_profile_id": pid})
        if "name" in payload:
            cfg = _read_config()
            profiles, _ = _ensure_quality_profiles(cfg)
            if pid in profiles:
                profiles[pid]["name"] = str(payload.get("name") or pid)
                cfg["quality_profiles"] = profiles
                _atomic_json(CONFIG_FILE, cfg)
                settings = _public_settings(cfg)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 409
    return jsonify({"ok": True, "settings": settings, "quality_profiles": _profiles_public(_read_config())})


@app.get("/api/inventory")
def inventory_status():
    inv = _quality_inventory(_read_config(), persist=False)
    latest = platform_store.load_inventory_latest(WEB_DATA_DIR) or inv
    return jsonify({"ok": True, "inventory": inv, "latest": latest})


@app.get("/api/inventory/history")
def inventory_history():
    limit = request.args.get("limit") or 48
    rows = platform_store.load_inventory_history(WEB_DATA_DIR, limit=limit)
    return jsonify({"ok": True, "history": rows})


@app.post("/api/inventory/snapshot")
def inventory_snapshot():
    inv = _quality_inventory(_read_config(), persist=True)
    return jsonify({"ok": True, "inventory": inv, "history": platform_store.load_inventory_history(WEB_DATA_DIR, limit=24)})


@app.get("/api/audit")
def audit_list():
    kind = request.args.get("kind") or ""
    limit = request.args.get("limit") or 50
    rows = platform_store.load_audit(WEB_DATA_DIR, kind=kind or None, limit=limit)
    return jsonify({"ok": True, "entries": rows})


@app.get("/download/<kind>/<path:filename>")
def download(kind, filename):
    if Path(filename).name != filename:
        abort(404)
    if kind == "accounts" and filename.endswith(".jsonl"):
        directory = ACCOUNT_DIR
    elif kind == "proxies" and filename.endswith(".txt"):
        directory = NODE_DIR
    else:
        abort(404)
    return send_from_directory(directory, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
