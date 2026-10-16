import io
import json
import unittest
from unittest.mock import patch
from urllib.request import Request

import kontist_balance


class KontistBalanceTests(unittest.TestCase):
    def test_fetches_meins_spendable_balance(self) -> None:
        response = io.BytesIO(
            json.dumps(
                {
                    "data": {
                        "viewer": {
                            "mainAccount": {
                                "stats": {
                                    "accountBalance": 123456,
                                    "taxTotal": 20000,
                                    "vatTotal": 10000,
                                    "yours": 73456,
                                }
                            }
                        }
                    }
                }
            ).encode()
        )
        with patch(
            "kontist_balance.urllib.request.urlopen", return_value=response
        ) as urlopen:
            balance = kontist_balance.fetch_yours_balance("test-token")

        self.assertEqual(balance, 73456)
        request = urlopen.call_args[0][0]
        self.assertIsInstance(request, Request)
        self.assertEqual(request.full_url, kontist_balance.API_URL)
        self.assertEqual(request.get_header("Authorization"), "Bearer test-token")
        self.assertIn(b"mainAccount", request.data)
        self.assertIn(b"stats", request.data)
        self.assertIn(b"yours", request.data)

    def test_rejects_empty_token(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty"):
            kontist_balance.fetch_yours_balance(" ")

    def test_reports_graphql_errors(self) -> None:
        response = io.BytesIO(
            json.dumps({"errors": [{"message": "Not authorized"}]}).encode()
        )
        with patch("kontist_balance.urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "Not authorized"):
                kontist_balance.fetch_yours_balance("test-token")

    def test_reports_missing_stats(self) -> None:
        response = io.BytesIO(json.dumps({"data": {"viewer": {}}}).encode())
        with patch("kontist_balance.urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "stats.yours"):
                kontist_balance.fetch_yours_balance("test-token")

    def test_reports_missing_yours_value(self) -> None:
        response = io.BytesIO(
            json.dumps(
                {
                    "data": {"viewer": {"mainAccount": {"stats": {"taxTotal": 20000}}}}
                }
            ).encode()
        )
        with patch("kontist_balance.urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(RuntimeError, "stats.yours"):
                kontist_balance.fetch_yours_balance("test-token")


if __name__ == "__main__":
    unittest.main()
