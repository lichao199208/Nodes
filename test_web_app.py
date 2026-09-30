import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import web_app as target


class DashboardApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.account_dir = root / "account"
        self.node_dir = root / "node"
        self.account_dir.mkdir()
        self.node_dir.mkdir()
        self.patches = [
            patch.object(target, "ACCOUNT_DIR", self.account_dir),
            patch.object(target, "NODE_DIR", self.node_dir),
        ]
        for item in self.patches:
            item.start()
        target.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        self.client = target.app.test_client()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def authenticate(self):
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["username"] = target.WEB_USERNAME
            session["csrf_token"] = "test-csrf"

    def test_health_does_not_require_login(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_dashboard_requires_login(self):
        self.assertEqual(self.client.get("/api/dashboard").status_code, 401)

    def test_accounts_list_hides_secrets_detail_shows_them(self):
        record = {
            "email": "masked@example.com",
            "password": "do-not-return",
            "access_token": "do-not-return-either",
            "account_id": "acc-1",
            "proxy_username": "user1",
            "proxy_password": "pass1",
            "verified": True,
            "trial_claimed": True,
            "proxy_count": 100,
            "ts": 1,
            "api_key": {
                "id": "key-1",
                "token": "public-api-token",
                "name": "nodes",
                "permissions": ["datacenter_shared:read"],
            },
        }
        (self.account_dir / "accounts_test.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
        self.authenticate()

        listed = self.client.get("/api/accounts")
        rendered = listed.get_data(as_text=True)
        self.assertEqual(listed.status_code, 200)
        self.assertIn("masked@example.com", rendered)
        self.assertNotIn("do-not-return", rendered)
        self.assertNotIn("public-api-token", rendered)
        self.assertTrue(listed.json["accounts"][0]["has_api_key"])

        detail = self.client.get("/api/accounts/masked@example.com")
        self.assertEqual(detail.status_code, 200)
        account = detail.json["account"]
        self.assertEqual(account["password"], "do-not-return")
        self.assertEqual(account["api_token"], "public-api-token")
        self.assertIn("datacenter_shared:read", account["permissions"])
        self.assertIn("/v4/account/acc-1/datacenter_shared/proxy-list", account["api"]["public_proxy_list"])

    def test_account_update_persists_password_and_permissions(self):
        record = {
            "email": "edit@example.com",
            "password": "old-pass",
            "verified": True,
            "ts": 1,
        }
        (self.account_dir / "accounts_test.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
        self.authenticate()

        response = self.client.put(
            "/api/accounts/edit@example.com",
            json={"password": "new-pass", "permissions": ["datacenter_shared:read", "subaccount:read"]},
            headers={"X-CSRF-Token": "test-csrf"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["account"]["password"], "new-pass")
        self.assertEqual(response.json["account"]["permissions"], ["datacenter_shared:read", "subaccount:read"])
        saved = (self.account_dir / "accounts_edits.jsonl").read_text(encoding="utf-8")
        self.assertIn("new-pass", saved)

    def test_task_creation_requires_csrf(self):
        self.authenticate()
        response = self.client.post("/api/tasks", json={"count": 1, "concurrency": 1})
        self.assertEqual(response.status_code, 403)

    @patch.object(target.TASK_STORE, "start_task")
    def test_task_creation_validates_and_starts(self, start):
        start.return_value = {"id": "task-1", "status": "queued"}
        self.authenticate()

        response = self.client.post(
            "/api/tasks",
            json={"count": 2, "concurrency": 2},
            headers={"X-CSRF-Token": "test-csrf"},
        )

        self.assertEqual(response.status_code, 202)
        start.assert_called_once_with(2, 2)


class TaskStoreTests(unittest.TestCase):
    @patch.object(target.worker, "register_one")
    def test_task_lifecycle_reaches_success(self, register_one):
        register_one.return_value = {"proxy_count": 100}
        with tempfile.TemporaryDirectory() as directory:
            store = target.TaskStore(Path(directory) / "tasks.json")

            task = store.start_task(2, 2)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                current = store.get(task["id"])
                if current["status"] not in {"queued", "running"}:
                    break
                time.sleep(0.01)

            self.assertEqual(current["status"], "success")
            self.assertEqual(current["completed"], 2)
            self.assertEqual(current["successes"], 2)
            self.assertEqual(current["proxy_count"], 200)
            self.assertEqual(register_one.call_count, 2)


class AccountOpsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.account_dir = root / "account"
        self.node_dir = root / "node"
        self.account_dir.mkdir()
        self.node_dir.mkdir()
        self.patches = [
            patch.object(target, "ACCOUNT_DIR", self.account_dir),
            patch.object(target, "NODE_DIR", self.node_dir),
        ]
        for item in self.patches:
            item.start()
        target.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        self.client = target.app.test_client()
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["username"] = target.WEB_USERNAME
            session["csrf_token"] = "test-csrf"

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def headers(self):
        return {"X-CSRF-Token": "test-csrf"}

    def write_account(self, record, name="accounts_test.jsonl"):
        path = self.account_dir / name
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def test_accounts_list_includes_expiry_and_remaining_bandwidth(self):
        expiry = int(time.time()) + 7 * 86400 + 3600
        self.write_account({
            "email": "usage@example.com",
            "verified": True,
            "proxy_count": 100,
            "ts": 1,
            "expiration_time": expiry,
            "bandwidth_total": 10000000000,
            "bandwidth_used": 2500000000,
            "bandwidth_remaining": 7500000000,
            "days_remaining": 7,
        })
        listed = self.client.get("/api/accounts")
        self.assertEqual(listed.status_code, 200)
        account = listed.json["accounts"][0]
        self.assertEqual(account["email"], "usage@example.com")
        self.assertEqual(account["expiry"], expiry)
        self.assertTrue(account["expires_at"])
        self.assertEqual(account["bandwidth_remaining"], 7500000000)
        self.assertFalse(account["expired"])
        self.assertNotIn("password", account)

    def test_delete_hides_account_and_import_restores_it(self):
        self.write_account({
            "email": "keep@example.com",
            "password": "secret",
            "verified": True,
            "ts": 1,
        })
        deleted = self.client.post(
            "/api/accounts/delete",
            json={"emails": ["keep@example.com"]},
            headers=self.headers(),
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertEqual(deleted.json["deleted"], ["keep@example.com"])
        self.assertEqual(self.client.get("/api/accounts").json["accounts"], [])

        imported = self.client.post(
            "/api/accounts/import",
            json={"text": json.dumps({"email": "keep@example.com", "password": "secret", "verified": True})},
            headers=self.headers(),
        )
        self.assertEqual(imported.status_code, 200)
        self.assertEqual(imported.json["imported"], 1)
        self.assertEqual(imported.json["restored"], 1)
        emails = [item["email"] for item in self.client.get("/api/accounts").json["accounts"]]
        self.assertEqual(emails, ["keep@example.com"])

    @patch.object(target.worker, "list_proxy_hosts", return_value=["10.0.0.1:10000", "10.0.0.2:10000"])
    @patch.object(target.worker, "fetch_accounts_summary", return_value=[])
    @patch.object(target.worker, "fetch_service_overview")
    def test_sync_usage_persists_expiry_and_remaining(self, overview, _summary, _hosts):
        expiry = int(time.time()) + 8 * 86400
        overview.return_value = {
            "bandwidth": 10000000000,
            "bandwidth_used": 1000000000,
            "bandwidth_period_end": expiry,
            "key": "account-key",
            "is_trial": True,
            "services": {
                "datacenter_shared": {
                    "proxy_username": "user1",
                    "proxy_password": "pass1",
                    "expiration_time": expiry,
                    "proxy_amount": 100,
                }
            },
        }
        self.write_account({
            "email": "sync@example.com",
            "access_token": "token",
            "account_id": "acc-1",
            "verified": True,
            "ts": 1,
        })
        response = self.client.post(
            "/api/accounts/sync-usage",
            json={"emails": ["sync@example.com"]},
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["synced"], ["sync@example.com"])
        account = response.json["accounts"][0]
        self.assertEqual(account["bandwidth_total"], 10000000000)
        self.assertEqual(account["bandwidth_used"], 1000000000)
        self.assertEqual(account["bandwidth_remaining"], 9000000000)
        self.assertEqual(account["expiry"], expiry)
        self.assertGreaterEqual(account["days_remaining"], 7)
        saved = (self.account_dir / "accounts_edits.jsonl").read_text(encoding="utf-8")
        self.assertIn("10.0.0.1:10000", saved)

    def test_overview_credentials_computes_remaining_traffic(self):
        expiry = int(time.time()) + 7 * 86400 + 3600
        creds = target.worker.overview_credentials({
            "bandwidth": 10000000000,
            "bandwidth_used": 2500000000,
            "bandwidth_period_end": expiry,
            "services": {
                "datacenter_shared": {
                    "proxy_username": "u",
                    "proxy_password": "p",
                    "expiration_time": expiry,
                    "proxy_amount": 100,
                }
            },
        })
        self.assertEqual(creds["bandwidth_remaining"], 7500000000)
        self.assertEqual(creds["expiration_time"], expiry)
        self.assertEqual(creds["days_remaining"], 7)


class PoolExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.account_dir = root / "account"
        self.node_dir = root / "node"
        self.account_dir.mkdir()
        self.node_dir.mkdir()
        self.patches = [
            patch.object(target, "ACCOUNT_DIR", self.account_dir),
            patch.object(target, "NODE_DIR", self.node_dir),
        ]
        for item in self.patches:
            item.start()
        target.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        self.client = target.app.test_client()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    def write_account(self, record):
        path = self.account_dir / "accounts_test.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def live_record(self, email, hosts, **extra):
        record = {
            "email": email,
            "verified": True,
            "proxy_username": extra.pop("proxy_username", email.split("@")[0]),
            "proxy_password": "pw",
            "proxy_ips": hosts,
            "expiration_time": extra.pop("expiration_time", int(time.time()) + 7 * 86400),
            "bandwidth_remaining": extra.pop("bandwidth_remaining", 9 * 1024 * 1024 * 1024),
            "ts": 1,
        }
        record.update(extra)
        return record

    def test_live_proxies_requires_token(self):
        response = self.client.get("/api/export/live-proxies")
        self.assertEqual(response.status_code, 401)

    def test_live_proxies_emits_eight_ips_per_live_account(self):
        hosts = [f"10.1.1.{index}:10000" for index in range(1, 13)]
        self.write_account(self.live_record("one@example.com", hosts, proxy_username="user-one"))
        self.write_account(self.live_record(
            "dead@example.com",
            ["9.9.9.9:1"],
            proxy_username="dead",
            expiration_time=int(time.time()) - 10,
        ))
        response = self.client.get("/api/export/live-proxies?token=test-export-token")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content_type.startswith("text/plain"))
        lines = [line for line in response.get_data(as_text=True).splitlines() if line.strip()]
        self.assertEqual(len(lines), 10)
        self.assertTrue(all(line.startswith("http://user-one:pw@") for line in lines))
        self.assertTrue(all("9.9.9.9" not in line for line in lines))
        again = self.client.get("/api/export/live-proxies?token=test-export-token")
        self.assertEqual(again.get_data(as_text=True), response.get_data(as_text=True))

    def test_live_proxies_harvests_missing_ips_from_node_files(self):
        self.write_account(self.live_record("two@example.com", [], proxy_username="user-two", proxy_ips=[]))
        (self.node_dir / "proxies_old.txt").write_text(
            "\n".join(f"http://user-two:pw@11.1.1.{index}:8080" for index in range(1, 14)) + "\n",
            encoding="utf-8",
        )
        response = self.client.get("/api/export/live-proxies?token=test-export-token")
        self.assertEqual(response.status_code, 200)
        lines = [line for line in response.get_data(as_text=True).splitlines() if line.strip()]
        self.assertEqual(len(lines), 10)
        self.assertTrue(all("user-two:pw@11.1.1." in line for line in lines))

    def test_live_proxies_scales_eight_slots_per_account(self):
        for index in range(1, 3):
            hosts = [f"10.{index}.1.{slot}:10000" for slot in range(1, 12)]
            self.write_account(self.live_record(
                f"acc{index}@example.com",
                hosts,
                proxy_username=f"user-{index}",
            ))
        response = self.client.get("/api/export/live-proxies?token=test-export-token")
        lines = [line for line in response.get_data(as_text=True).splitlines() if line.strip()]
        self.assertEqual(len(lines), 20)
        self.assertEqual(sum(1 for line in lines if "user-1:pw@" in line), 10)
        self.assertEqual(sum(1 for line in lines if "user-2:pw@" in line), 10)

    @patch.object(target.pool, "resin_auth", return_value=("gw-token", "V1"))
    def test_gpt_gateway_matches_live_slot_count(self, _auth):
        for index in range(1, 3):
            hosts = [f"10.{index}.1.{slot}:10000" for slot in range(1, 12)]
            self.write_account(self.live_record(
                f"acc{index}@example.com",
                hosts,
                proxy_username=f"user-{index}",
            ))
        response = self.client.get("/api/export/gpt-gateway?token=test-export-token")
        self.assertEqual(response.status_code, 200)
        lines = [line for line in response.get_data(as_text=True).splitlines() if line.strip()]
        self.assertEqual(len(lines), 20)
        self.assertTrue(all(":8970" in line for line in lines))
        self.assertTrue(all("Nodes.n" in line for line in lines))
        self.assertIn("Nodes.n01:", lines[0])
        self.assertIn("Nodes.n20:", lines[-1])

    @patch.object(target.pool, "resin_auth", return_value=("gw-token", "V1"))
    def test_clash_export_matches_live_slot_count(self, _auth):
        for index in range(1, 3):
            hosts = [f"10.{index}.1.{slot}:10000" for slot in range(1, 12)]
            self.write_account(self.live_record(
                f"acc{index}@example.com",
                hosts,
                proxy_username=f"user-{index}",
            ))
        denied = self.client.get("/api/export/clash.yml")
        self.assertEqual(denied.status_code, 401)
        response = self.client.get("/api/export/clash.yml?token=test-export-token")
        self.assertEqual(response.status_code, 200)
        body = response.get_data(as_text=True)
        self.assertIn("type: http", body)
        self.assertNotIn("type: socks5", body)
        self.assertNotIn(":8970", body)
        self.assertIn("节点 01", body)
        self.assertIn("节点 20", body)
        self.assertEqual(body.count("type: http"), 20)
        self.assertIn("username: \"user-1\"", body)
        self.assertIn('server: "10.1.1.1"', body)

    def test_clash_profile_keeps_fastest_in_each_country(self):
        entries = [{
            "proxy_username": "user-1",
            "proxy_password": "pw",
            "slots": ["1.1.1.1:3129", "1.1.1.2:3129", "2.2.2.1:3129", "2.2.2.2:3129"],
        }]
        regions = {"1.1.1.1": "us", "1.1.1.2": "us", "2.2.2.1": "de", "2.2.2.2": "de"}
        latency = {"1.1.1.1": 500, "1.1.1.2": 40, "2.2.2.1": 300, "2.2.2.2": 50}
        body = target.pool.clash_profile(entries, regions, latency, per_country=1)
        self.assertIn("1.1.1.2", body)
        self.assertNotIn("1.1.1.1", body)
        self.assertIn("2.2.2.2", body)
        self.assertNotIn("2.2.2.1", body)
        self.assertIn("美国", body)
        self.assertIn("德国", body)

    @patch.object(target.pool, "resin_auth", return_value=("gw-token", "V1"))
    def test_clash_export_accepts_query_token_even_with_dummy_bearer(self, _auth):
        hosts = [f"10.1.1.{slot}:10000" for slot in range(1, 12)]
        self.write_account(self.live_record("acc1@example.com", hosts, proxy_username="user-1"))
        response = self.client.get(
            "/api/export/clash.yml?token=test-export-token",
            headers={"Authorization": "Bearer wrong-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("filename=\"clash.yml\"", response.headers.get("Content-Disposition", ""))
        path_ok = self.client.get("/api/export/clash.yml/test-export-token")
        self.assertEqual(path_ok.status_code, 200)
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["username"] = target.WEB_USERNAME
        logged_in = self.client.get("/api/export/clash.yml")
        self.assertEqual(logged_in.status_code, 200)

    @patch.object(target.pool, "resin_auth", return_value=("gw-token", "V1"))
    def test_ladder_export_is_base64_uri_list(self, _auth):
        import base64
        hosts = [f"10.1.1.{slot}:10000" for slot in range(1, 12)]
        self.write_account(self.live_record("acc1@example.com", hosts, proxy_username="user-1"))
        response = self.client.get("/api/export/ladder?token=test-export-token")
        self.assertEqual(response.status_code, 200)
        decoded = base64.b64decode(response.get_data(as_text=True).strip()).decode("utf-8")
        lines = [line for line in decoded.splitlines() if line.strip()]
        self.assertEqual(len(lines), 10)
        self.assertTrue(all(line.startswith("http://Nodes.n") for line in lines))
        self.assertTrue(all(":8970#" in line for line in lines))

    @patch.object(target.TASK_STORE, "active", return_value=None)
    @patch.object(target.TASK_STORE, "start_task")
    def test_ensure_capacity_starts_register_task_when_short(self, start, _active):
        start.return_value = {"id": "task-fill", "status": "queued"}
        with self.client.session_transaction() as session:
            session["authenticated"] = True
            session["username"] = target.WEB_USERNAME
            session["csrf_token"] = "test-csrf"
        response = self.client.post(
            "/api/pool/ensure-capacity",
            json={"auto_register": True},
            headers={"X-CSRF-Token": "test-csrf"},
        )
        self.assertEqual(response.status_code, 200)
        start.assert_called_once_with(5, 1)
        self.assertEqual(response.json["task"]["id"], "task-fill")


class MailboxLocalTests(unittest.TestCase):
    def test_random_mailbox_local_is_not_serial_ps_prefix(self):
        samples = [target.worker.random_mailbox_local() for _ in range(200)]
        self.assertEqual(len(samples), 200)
        self.assertEqual(len(set(samples)), 200)
        prefixes = {}
        lengths = set()
        for local in samples:
            self.assertTrue(re.fullmatch(r"[a-z][a-z0-9]{7,15}", local), local)
            self.assertFalse(local.startswith(("ps", "test", "admin", "user", "mail", "temp", "tmp")))
            prefixes[local[:2]] = prefixes.get(local[:2], 0) + 1
            lengths.add(len(local))
        self.assertGreaterEqual(len(prefixes), 20)
        self.assertGreaterEqual(len(lengths), 2)
        self.assertLess(max(prefixes.values()) / len(samples), 0.25)


if __name__ == "__main__":
    unittest.main()
