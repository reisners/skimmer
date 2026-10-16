import base64
import io
import json
import time
import unittest
import urllib.parse
from unittest.mock import patch
from urllib.request import Request

import kontist_token


def api_response(data):
    return io.BytesIO(json.dumps(data).encode("utf-8"))


class KontistTokenTests(unittest.TestCase):
    def test_fetches_and_confirms_access_token(self):
        expires_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300)
        )
        responses = [
            api_response({"access_token": "unconfirmed-token"}),
            api_response({"id": "challenge-1", "expiresAt": expires_at}),
            api_response({"status": "PENDING"}),
            api_response({"status": "VERIFIED"}),
            api_response({"token": "confirmed-token"}),
        ]
        with patch(
            "kontist_token._get_authorization_code", return_value="auth-code"
        ):
            with patch(
                "kontist_token.urllib.request.urlopen", side_effect=responses
            ) as urlopen:
                with patch("kontist_token.time.sleep"):
                    token = kontist_token.fetch_confirmed_access_token(
                        "client-id", "client-secret"
                    )

        self.assertEqual(token, "confirmed-token")
        requests = [item[0][0] for item in urlopen.call_args_list]
        self.assertTrue(all(isinstance(request, Request) for request in requests))
        self.assertEqual(
            requests[0].full_url, kontist_token.API_URL + kontist_token.TOKEN_PATH
        )
        self.assertEqual(
            requests[0].get_header("Authorization"),
            "Basic "
            + base64.b64encode(b"client-id:client-secret").decode("ascii"),
        )
        form = urllib.parse.parse_qs(requests[0].data.decode("ascii"))
        self.assertEqual(form["grant_type"], ["authorization_code"])
        self.assertEqual(form["code"], ["auth-code"])
        self.assertEqual(form["redirect_uri"], [kontist_token.REDIRECT_URI])
        self.assertEqual(
            [request.get_method() for request in requests],
            ["POST", "POST", "GET", "GET", "POST"],
        )
        self.assertEqual(
            requests[1].get_header("Authorization"), "Bearer unconfirmed-token"
        )

    def test_authorization_url_uses_state_and_registered_redirect(self):
        with patch("kontist_token.secrets.token_urlsafe", return_value="random-state"):
            with patch("kontist_token.webbrowser.open", return_value=False) as open_browser:
                with patch("kontist_token.HTTPServer") as server_factory:
                    server = server_factory.return_value.__enter__.return_value
                    server.handle_request.side_effect = lambda: None
                    with patch("kontist_token.time.time", side_effect=[0, 301]):
                        with self.assertRaisesRegex(RuntimeError, "Timed out"):
                            kontist_token._get_authorization_code("client-id")

        authorization_url = open_browser.call_args[0][0]
        parsed_url = urllib.parse.urlsplit(authorization_url)
        self.assertEqual(
            parsed_url.path, kontist_token.AUTHORIZATION_PATH
        )
        query = urllib.parse.parse_qs(parsed_url.query)
        self.assertEqual(query["client_id"], ["client-id"])
        self.assertEqual(query["redirect_uri"], [kontist_token.REDIRECT_URI])
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["scope"], [kontist_token.SCOPES])
        self.assertEqual(query["state"], ["random-state"])

    def test_rejects_callback_with_wrong_state(self):
        with self.assertRaisesRegex(RuntimeError, "state did not match"):
            kontist_token._authorization_code_from_callback(
                "code=secret-code&state=wrong", "expected-state"
            )

    def test_rejects_oauth_error_callback(self):
        query = urllib.parse.urlencode(
            {"error": "access_denied", "state": "expected-state"}
        )
        with self.assertRaisesRegex(RuntimeError, "access_denied"):
            kontist_token._authorization_code_from_callback(query, "expected-state")

    def test_rejects_missing_client_credentials(self):
        with self.assertRaisesRegex(ValueError, "client ID and client secret"):
            kontist_token.fetch_confirmed_access_token("", "secret")

    def test_rejects_denied_mfa_challenge(self):
        expires_at = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 300)
        )
        responses = [
            api_response({"access_token": "unconfirmed-token"}),
            api_response({"id": "challenge-1", "expiresAt": expires_at}),
            api_response({"status": "DENIED"}),
        ]
        with patch(
            "kontist_token._get_authorization_code", return_value="auth-code"
        ):
            with patch(
                "kontist_token.urllib.request.urlopen", side_effect=responses
            ):
                with self.assertRaisesRegex(RuntimeError, "was denied"):
                    kontist_token.fetch_confirmed_access_token(
                        "client-id", "client-secret"
                    )


if __name__ == "__main__":
    unittest.main()
