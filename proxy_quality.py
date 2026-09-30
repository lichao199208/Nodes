# -*- coding: utf-8 -*-
"""Proxy quality gate for Nodes-ops pull/export pools.

Maps user requirements onto concrete checks (aligned with newbanana Adobe ARP):

  User term                         Implementation
  --------------------------------  ----------------------------------------------
  ARP = sid/ark/bfp/ftr + v2_tt     validate_arp4_token() — same rules as
                                    adobe.DecodePoolARPToken (sid/ark/bfp/ftr
                                    present; ftr must contain ``v2_tt``)
  v2_tt publish 200                 proxy Adobe path probe OK; optional POST to
                                    configured arp_publish_url must return HTTP 200
  低延迟                             latency_ms <= proxy_max_latency_ms
  不要美国代理                       egress country not US / United States

A proxy is admitted only when geo + latency + ARP-path checks all pass.
ARP4 token validation is used when a publish payload is available; for raw
proxy URLs we probe Adobe reachability as the path gate (harvester still
enforces full ARP4 + publish 200 at mint time).
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests

DEFAULT_MAX_LATENCY_MS = 3000
DEFAULT_TIMEOUT_SEC = 12.0
DEFAULT_WORKERS = 16
DEFAULT_CACHE_TTL_SEC = 600
DEFAULT_GEO_URL = "http://ip-api.com/json/?fields=status,message,country,countryCode,query"
# Firefly 3p is the Adobe surface ARP mint/submit traffic touches.
DEFAULT_ARP_PROBE_URL = "https://firefly-3p.ff.adobe.io/"
DEFAULT_EXCLUDE_COUNTRIES = ("US",)

_US_NAMES = {"us", "usa", "united states", "united states of america"}
_PROXY_RE = re.compile(
    r"^(?:(?P<scheme>https?|socks5h?|socks)://)?(?:(?P<user>[^:@/]+):(?P<password>[^@/]+)@)?"
    r"(?P<host>\[[^\]]+\]|[^:/\s]+):(?P<port>\d+)\s*$",
    re.I,
)

_cache_lock = threading.Lock()
_memory_cache = {}


def _as_bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value, default, minimum=None, maximum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        number = default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def quality_settings(config=None):
    data = config if isinstance(config, dict) else {}
    exclude_raw = data.get("proxy_exclude_countries")
    if isinstance(exclude_raw, str):
        exclude = [part.strip().upper() for part in exclude_raw.replace(";", ",").split(",") if part.strip()]
    elif isinstance(exclude_raw, (list, tuple)):
        exclude = [str(part).strip().upper() for part in exclude_raw if str(part).strip()]
    else:
        exclude = list(DEFAULT_EXCLUDE_COUNTRIES)
    if not exclude:
        exclude = list(DEFAULT_EXCLUDE_COUNTRIES)
    return {
        "enabled": _as_bool(data.get("proxy_quality_enabled"), True),
        "max_latency_ms": _as_int(
            data.get("proxy_max_latency_ms"), DEFAULT_MAX_LATENCY_MS, 200, 60000,
        ),
        "timeout_sec": max(3.0, min(60.0, float(data.get("proxy_quality_timeout_sec") or DEFAULT_TIMEOUT_SEC))),
        "workers": _as_int(data.get("proxy_quality_workers"), DEFAULT_WORKERS, 1, 64),
        "cache_ttl_sec": _as_int(
            data.get("proxy_quality_cache_ttl_sec"), DEFAULT_CACHE_TTL_SEC, 30, 86400,
        ),
        "exclude_countries": exclude,
        "geo_url": str(data.get("proxy_geo_url") or DEFAULT_GEO_URL).strip() or DEFAULT_GEO_URL,
        "arp_check_enabled": _as_bool(data.get("proxy_arp_check_enabled"), True),
        "arp_probe_url": str(data.get("proxy_arp_probe_url") or DEFAULT_ARP_PROBE_URL).strip() or DEFAULT_ARP_PROBE_URL,
        "arp_publish_url": str(data.get("arp_publish_url") or "").strip(),
        "arp_publish_token": str(data.get("arp_publish_token") or "").strip(),
    }


def normalize_proxy_url(raw, default_scheme="http"):
    text = str(raw or "").strip()
    if not text or text.startswith("#"):
        return ""
    if "://" not in text:
        text = f"{default_scheme}://{text}"
    return text


def proxy_identity(proxy_url):
    """Stable host:port key for cache / slot filtering."""
    text = normalize_proxy_url(proxy_url)
    if not text:
        return ""
    match = _PROXY_RE.match(text)
    if match:
        host = match.group("host")
        port = match.group("port")
        return f"{host}:{port}"
    parsed = urlparse(text)
    if parsed.hostname and parsed.port:
        return f"{parsed.hostname}:{parsed.port}"
    if parsed.netloc:
        return parsed.netloc.split("@")[-1]
    return text


def is_excluded_country(country_code, country_name, exclude_countries):
    code = str(country_code or "").strip().upper()
    name = str(country_name or "").strip().lower()
    blocked = {str(item).strip().upper() for item in (exclude_countries or []) if str(item).strip()}
    if code and code in blocked:
        return True
    if "US" in blocked and name in _US_NAMES:
        return True
    if name in _US_NAMES and any(item in {"US", "USA"} for item in blocked):
        return True
    return False


def validate_arp4_token(token):
    """Validate ARP4 token: sid + ark + bfp + ftr, and ftr contains v2_tt.

    Mirrors newbanana ``adobe.DecodePoolARPToken``.
    """
    text = str(token or "").strip()
    if not text:
        return False, "empty ARP token"
    raw = None
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = text + ("=" * (-len(text) % 4))
            raw = decoder(padded)
            break
        except Exception:
            continue
    if raw is None:
        return False, "ARP token must be base64-encoded JSON"
    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False, "ARP token must be base64-encoded JSON"
    if not isinstance(payload, dict):
        return False, "ARP token JSON must be an object"
    parts = {}
    for key in ("sid", "ark", "bfp", "ftr"):
        value = str(payload.get(key) or "").strip()
        if not value:
            return False, f"ARP token is missing required parts: {key}"
        parts[key] = value
    if "v2_tt" not in parts["ftr"]:
        return False, "ARP token ftr must be the full forter cookie with v2_tt"
    return True, parts


def arp_publish_status_ok(status_code):
    """User requirement: v2_tt publish must be HTTP 200."""
    try:
        return int(status_code) == 200
    except (TypeError, ValueError):
        return False


def _session_for_proxy(proxy_url):
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "nodes-ops-proxy-quality/1.0"})
    session.proxies = {"http": proxy_url, "https": proxy_url}
    return session


def _coerce_settings(settings=None):
    data = settings if isinstance(settings, dict) else {}
    # Already normalized by quality_settings().
    if "max_latency_ms" in data and "exclude_countries" in data and "enabled" in data:
        return data
    return quality_settings(data)


def probe_proxy(proxy_url, settings=None):
    """Run geo + latency + ARP-path checks for one proxy URL."""
    cfg = _coerce_settings(settings)
    url = normalize_proxy_url(proxy_url)
    started = time.monotonic()
    result = {
        "proxy": url,
        "identity": proxy_identity(url),
        "ok": False,
        "latency_ms": 0,
        "country": "",
        "country_code": "",
        "egress_ip": "",
        "arp_ok": False,
        "arp_status": 0,
        "publish_status": 0,
        "reason": "",
    }
    if not url:
        result["reason"] = "empty proxy"
        return result
    if not cfg["enabled"]:
        result["ok"] = True
        result["reason"] = "quality filter disabled"
        return result

    session = _session_for_proxy(url)
    try:
        geo = session.get(cfg["geo_url"], timeout=cfg["timeout_sec"])
        latency_ms = int((time.monotonic() - started) * 1000)
        result["latency_ms"] = latency_ms
        try:
            payload = geo.json()
        except Exception:
            payload = {}
        if geo.status_code != 200 or str(payload.get("status") or "").lower() == "fail":
            result["reason"] = f"geo probe failed HTTP {geo.status_code}"
            return result
        result["country"] = str(payload.get("country") or "")
        result["country_code"] = str(payload.get("countryCode") or payload.get("country_code") or "").upper()
        result["egress_ip"] = str(payload.get("query") or payload.get("ip") or "")
        if is_excluded_country(result["country_code"], result["country"], cfg["exclude_countries"]):
            result["reason"] = f"excluded country {result['country_code'] or result['country'] or 'US'}"
            return result
        if latency_ms > int(cfg["max_latency_ms"]):
            result["reason"] = f"latency {latency_ms}ms > {cfg['max_latency_ms']}ms"
            return result

        if cfg["arp_check_enabled"]:
            arp_started = time.monotonic()
            try:
                arp_resp = session.get(
                    cfg["arp_probe_url"],
                    timeout=cfg["timeout_sec"],
                    allow_redirects=True,
                )
                # Any HTTP response through the tunnel means Adobe path is reachable.
                result["arp_status"] = int(arp_resp.status_code or 0)
                result["arp_ok"] = result["arp_status"] > 0
            except requests.RequestException as exc:
                result["reason"] = f"ARP path probe failed: {str(exc).splitlines()[0][:160]}"
                result["latency_ms"] = max(result["latency_ms"], int((time.monotonic() - arp_started) * 1000))
                return result
            if not result["arp_ok"]:
                result["reason"] = "ARP path probe returned no HTTP status"
                return result

            publish_url = cfg["arp_publish_url"]
            if publish_url:
                headers = {"Content-Type": "application/json"}
                if cfg["arp_publish_token"]:
                    headers["X-Internal-Token"] = cfg["arp_publish_token"]
                try:
                    # Empty tokens list → upstream should 400; we only accept explicit 200
                    # from a dedicated health/publish-ready probe URL.
                    pub = session.post(
                        publish_url,
                        headers=headers,
                        json={"probe": True, "require": ["sid", "ark", "bfp", "ftr", "v2_tt"]},
                        timeout=cfg["timeout_sec"],
                    )
                    result["publish_status"] = int(pub.status_code or 0)
                except requests.RequestException as exc:
                    result["reason"] = f"ARP publish probe failed: {str(exc).splitlines()[0][:160]}"
                    return result
                if not arp_publish_status_ok(result["publish_status"]):
                    result["reason"] = f"ARP publish status {result['publish_status']} (need 200)"
                    return result

        result["ok"] = True
        result["reason"] = "ok"
        return result
    except requests.RequestException as exc:
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        result["reason"] = str(exc).splitlines()[0][:160]
        return result
    finally:
        session.close()


def _cache_path(data_dir):
    if not data_dir:
        return None
    return Path(data_dir) / "proxy_quality_cache.json"


def load_cache(data_dir):
    path = _cache_path(data_dir)
    if not path or not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_cache(data_dir, cache):
    path = _cache_path(data_dir)
    if not path:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def cache_get(identity, data_dir, ttl_sec):
    if not identity:
        return None
    now = time.time()
    with _cache_lock:
        item = _memory_cache.get(identity)
        if item and now - float(item.get("checked_at") or 0) <= ttl_sec:
            return item
    disk = load_cache(data_dir)
    item = disk.get(identity) if isinstance(disk, dict) else None
    if item and now - float(item.get("checked_at") or 0) <= ttl_sec:
        with _cache_lock:
            _memory_cache[identity] = item
        return item
    return None


def cache_put(result, data_dir):
    identity = result.get("identity") or proxy_identity(result.get("proxy"))
    if not identity:
        return
    item = dict(result)
    item["checked_at"] = time.time()
    with _cache_lock:
        _memory_cache[identity] = item
        disk = load_cache(data_dir)
        disk[identity] = item
        # Keep cache bounded.
        if len(disk) > 5000:
            ordered = sorted(disk.items(), key=lambda pair: float(pair[1].get("checked_at") or 0), reverse=True)
            disk = dict(ordered[:4000])
        save_cache(data_dir, disk)


def filter_proxies(proxy_urls, settings=None, data_dir=None, use_cache=True, probe_missing=True):
    """Return (accepted_urls, report) after quality filtering."""
    cfg = quality_settings(settings)
    urls = []
    seen = set()
    for raw in proxy_urls or []:
        url = normalize_proxy_url(raw)
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)

    if not cfg["enabled"]:
        return list(urls), {
            "scanned": len(urls),
            "accepted": len(urls),
            "rejected": 0,
            "enabled": False,
            "results": [{"proxy": item, "ok": True, "reason": "disabled"} for item in urls],
        }

    accepted = []
    results = []
    pending = []
    skipped = 0
    for url in urls:
        identity = proxy_identity(url)
        cached = cache_get(identity, data_dir, cfg["cache_ttl_sec"]) if use_cache else None
        if cached is not None:
            row = dict(cached)
            row["proxy"] = url
            results.append(row)
            if row.get("ok"):
                accepted.append(url)
            continue
        if not probe_missing:
            skipped += 1
            results.append({
                "proxy": url,
                "identity": identity,
                "ok": False,
                "reason": "not probed yet",
            })
            continue
        pending.append(url)

    if pending:
        workers = max(1, min(int(cfg["workers"]), len(pending)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(probe_proxy, url, cfg): url for url in pending}
            for future in as_completed(futures):
                row = future.result()
                results.append(row)
                cache_put(row, data_dir)
                if row.get("ok"):
                    accepted.append(row["proxy"])

    # Preserve input order for accepted list.
    order = {url: index for index, url in enumerate(urls)}
    accepted.sort(key=lambda item: order.get(item, 10**9))
    return accepted, {
        "scanned": len(urls),
        "accepted": len(accepted),
        "rejected": len(urls) - len(accepted),
        "skipped_unprobed": skipped,
        "enabled": True,
        "max_latency_ms": cfg["max_latency_ms"],
        "exclude_countries": cfg["exclude_countries"],
        "arp_check_enabled": cfg["arp_check_enabled"],
        "results": results,
    }


def rewrite_scheme(proxy_url, scheme):
    text = normalize_proxy_url(proxy_url)
    if not text:
        return ""
    wanted = str(scheme or "http").strip().lower()
    if wanted in {"socks5", "socks"}:
        wanted = "socks5h"
    if wanted not in {"http", "socks5h"}:
        wanted = "http"
    parsed = urlparse(text)
    rest = text.split("://", 1)[-1]
    if parsed.scheme:
        return f"{wanted}://{rest}"
    return f"{wanted}://{text}"


def filter_host_list(hosts, user, password, settings=None, data_dir=None, scheme="http",
                     use_cache=True, probe_missing=True):
    """Filter host:port slots by building temporary proxy URLs."""
    from urllib.parse import quote

    scheme = "socks5h" if str(scheme or "").lower() in {"socks5", "socks", "socks5h"} else "http"
    urls = []
    host_by_url = {}
    for host in hosts or []:
        host_text = str(host or "").strip()
        if not host_text:
            continue
        url = f"{scheme}://{quote(str(user or ''), safe='')}:{quote(str(password or ''), safe='')}@{host_text}"
        urls.append(url)
        host_by_url[url] = host_text
    accepted_urls, report = filter_proxies(
        urls, settings=settings, data_dir=data_dir, use_cache=use_cache, probe_missing=probe_missing,
    )
    accepted_hosts = [host_by_url[url] for url in accepted_urls if url in host_by_url]
    return accepted_hosts, report
