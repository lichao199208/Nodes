import unittest
import os
import stat
import tempfile
from unittest.mock import Mock, patch

import proxyscrape_register as target


class TwoCaptchaSolverTests(unittest.TestCase):
    def setUp(self):
        self.original_key = target.CAPTCHA_API_KEY
        self.original_interval = target.CAPTCHA_POLL_INTERVAL
        target.CAPTCHA_API_KEY = "YOUR_SECRET_HERE"
        target.CAPTCHA_POLL_INTERVAL = 5

    def tearDown(self):
        target.CAPTCHA_API_KEY = self.original_key
        target.CAPTCHA_POLL_INTERVAL = self.original_interval

    @patch.object(target.time, "sleep")
    @patch.object(target, "_captcha_post")
    def test_returns_ready_token(self, post, _sleep):
        post.side_effect = [
            {"errorId": 0, "taskId": 123},
            {"errorId": 0, "status": "processing"},
            {
                "errorId": 0,
                "status": "ready",
                "solution": {"token": "turnstile-token"},
                "cost": "0.00145",
            },
        ]

        token = target.solve_turnstile_2captcha(timeout=30)

        self.assertEqual(token, "turnstile-token")
        self.assertEqual(post.call_count, 3)
        self.assertEqual(post.call_args_list[0].args[0], "/createTask")
        self.assertEqual(post.call_args_list[1].args[0], "/getTaskResult")

    @patch.object(target, "_captcha_post")
    def test_rejects_create_response_without_task_id(self, post):
        post.return_value = {"errorId": 0}

        with self.assertRaisesRegex(RuntimeError, "未返回 taskId"):
            target.solve_turnstile_2captcha(timeout=30)

    @patch.object(target.time, "sleep")
    @patch.object(target.time, "monotonic", side_effect=[0, 0, 6])
    @patch.object(target, "_captcha_post")
    def test_times_out_while_processing(self, post, _monotonic, _sleep):
        post.side_effect = [
            {"errorId": 0, "taskId": 456},
            {"errorId": 0, "status": "processing"},
        ]

        with self.assertRaisesRegex(TimeoutError, "求解超时"):
            target.solve_turnstile_2captcha(timeout=5)

    @patch.object(target, "solve_turnstile_2captcha", return_value="token")
    def test_dispatches_to_2captcha(self, solve):
        original_provider = target.CAPTCHA_PROVIDER
        target.CAPTCHA_PROVIDER = "2captcha"
        try:
            self.assertEqual(target.solve_turnstile(headless=True), "token")
            solve.assert_called_once_with(timeout=None)
        finally:
            target.CAPTCHA_PROVIDER = original_provider


class TwoCaptchaApiTests(unittest.TestCase):
    @patch.object(target.requests, "post")
    def test_raises_api_error_code(self, post):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "errorId": 10,
            "errorCode": "ERROR_ZERO_BALANCE",
            "errorDescription": "Account has zero balance",
        }
        post.return_value = response

        with self.assertRaisesRegex(RuntimeError, "ERROR_ZERO_BALANCE"):
            target._captcha_post("/createTask", {})


class PremiumTrialTests(unittest.TestCase):
    def test_already_claimed_does_not_post(self):
        session = Mock()
        eligibility = Mock()
        eligibility.json.return_value = {"success": True, "claimed": True}
        eligibility.raise_for_status.return_value = None
        session.get.return_value = eligibility

        account_id = target.ensure_premium_trial(session, "token")

        self.assertIsNone(account_id)
        session.post.assert_not_called()

    def test_claims_trial_and_returns_account_id(self):
        session = Mock()
        eligibility = Mock()
        eligibility.json.return_value = {"success": True, "claimed": False}
        eligibility.raise_for_status.return_value = None
        claim = Mock(ok=True, status_code=200)
        claim.json.return_value = {
            "success": True,
            "account_id": "account-123",
            "message": "Trial claimed",
        }
        session.get.return_value = eligibility
        session.post.return_value = claim

        account_id = target.ensure_premium_trial(session, "token")

        self.assertEqual(account_id, "account-123")
        session.post.assert_called_once_with(
            target.PS_CLAIM_TRIAL,
            headers={"Authorization": "Bearer token"},
            json={},
            timeout=30,
        )

    @patch.object(target, "get_current_user")
    @patch.object(target, "ensure_premium_trial", return_value="account-123")
    def test_uses_claim_response_while_user_data_refreshes(self, _claim, current_user):
        current_user.return_value = {
            "EmailVerified": True,
            "associatedSubaccounts": [],
        }

        userdata, account_id = target.activate_trial_and_get_account(Mock(), "token")

        self.assertEqual(account_id, "account-123")
        self.assertTrue(userdata["EmailVerified"])


class RegistrationLoggingTests(unittest.TestCase):
    @patch.object(target, "log")
    @patch.object(target.requests, "Session")
    def test_access_token_is_redacted_from_logs(self, session_factory, log):
        response = Mock(ok=True, status_code=200, content=b"response")
        response.json.return_value = {
            "access_token": "secret-token-value",
            "userData": {"EmailVerified": False},
        }
        session = session_factory.return_value
        session.post.return_value = response

        _session, token, _userdata = target.register("a@example.com", "pw", "captcha")

        self.assertEqual(token, "secret-token-value")
        rendered = " ".join(str(call.args[0]) for call in log.call_args_list)
        self.assertNotIn("secret-token-value", rendered)
        self.assertIn("<redacted>", rendered)


class PrivateOutputTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX mode bits are verified in the Linux image")
    def test_account_output_is_owner_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "accounts.jsonl")

            target.save_account({"access_token": "secret"}, path)

            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
