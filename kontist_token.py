"""Obtain a confirmed Kontist access token using browser OAuth and push MFA.

Register REDIRECT_URI with your Kontist API client. Set KONTIST_CLIENT_ID and
KONTIST_CLIENT_SECRET, then run this script. The confirmed access token is
written to stdout only.
"""

import base64
import calendar
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

API_URL = "https://api.kontist.com"
AUTHORIZATION_PATH = "/api/oauth/authorize"
TOKEN_PATH = "/api/oauth/token"
CHALLENGE_PATH = "/api/user/mfa/challenges"
POLL_INTERVAL_SECONDS = 3
REDIRECT_URI = "http://127.0.0.1:8765/callback"
CALLBACK_TIMEOUT_SECONDS = 300
SCOPES = "transactions"


def _request_json(
    path: str,
    method: str,
    payload: Optional[Dict[str, str]] = None,
    access_token: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    data = None

    if payload is not None:
        data = urllib.parse.urlencode(payload).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
    if client_id is not None and client_secret is not None:
        credentials = (client_id + ":" + client_secret).encode("utf-8")
        encoded_credentials = base64.b64encode(credentials).decode("ascii")
        headers["Authorization"] = "Basic " + encoded_credentials

    request = urllib.request.Request(
        API_URL + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            "Kontist API returned HTTP {} ({}).".format(error.code, error.reason)
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(
            "Could not connect to the Kontist API: {}".format(error.reason)
        ) from error

    if not isinstance(result, dict):
        raise RuntimeError("Kontist API returned an unexpected response.")
    return result


def _expires_at_epoch(value: Any) -> float:
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?"
        r"(Z|[+-]\d{2}:\d{2})$",
        value if isinstance(value, str) else "",
    )
    if match is None:
        raise RuntimeError("Kontist returned an invalid MFA challenge expiry time.")

    timestamp = calendar.timegm(time.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S"))
    fractional = match.group(2) or ""
    if fractional:
        timestamp += float("0." + fractional)

    timezone = match.group(3)
    if timezone != "Z":
        offset_hours = int(timezone[1:3])
        offset_minutes = int(timezone[4:6])
        if offset_hours > 23 or offset_minutes > 59:
            raise RuntimeError("Kontist returned an invalid MFA challenge expiry time.")
        offset_seconds = offset_hours * 3600 + offset_minutes * 60
        if timezone[0] == "-":
            offset_seconds = -offset_seconds
        timestamp -= offset_seconds
    return timestamp


def _authorization_code_from_callback(query: str, expected_state: str) -> str:
    parameters = urllib.parse.parse_qs(query, keep_blank_values=True)
    returned_state = parameters.get("state", [""])[0]
    if not secrets.compare_digest(returned_state, expected_state):
        raise RuntimeError("OAuth state did not match; rejecting the callback.")
    if parameters.get("error"):
        raise RuntimeError(
            "Kontist authorization failed: {}".format(parameters["error"][0])
        )
    code = parameters.get("code", [""])[0]
    if not code:
        raise RuntimeError("Kontist callback did not include an authorization code.")
    return code


def _get_authorization_code(client_id: str) -> str:
    state = secrets.token_urlsafe(32)
    redirect = urllib.parse.urlsplit(REDIRECT_URI)
    if (
        redirect.scheme != "http"
        or redirect.hostname != "127.0.0.1"
        or redirect.port is None
        or redirect.path != "/callback"
        or redirect.query
        or redirect.fragment
    ):
        raise RuntimeError("The configured OAuth redirect URI is invalid.")

    authorization_url = API_URL + AUTHORIZATION_PATH + "?" + urllib.parse.urlencode(
        {
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": SCOPES,
            "state": state,
        }
    )
    result = []

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            callback = urllib.parse.urlsplit(self.path)
            if callback.path != redirect.path:
                self.send_error(404)
                return
            try:
                code = _authorization_code_from_callback(callback.query, state)
            except RuntimeError as error:
                result.append(error)
                body = b"Kontist authorization failed. You can close this tab."
                self.send_response(400)
            else:
                result.append(code)
                body = b"Kontist authorization received. You can close this tab."
                self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    try:
        server = HTTPServer((redirect.hostname, redirect.port), CallbackHandler)
    except OSError as error:
        raise RuntimeError(
            "Could not start the local OAuth callback server at {}: {}".format(
                REDIRECT_URI, error
            )
        ) from error

    print("Opening Kontist authorization in your browser...", file=sys.stderr)
    with server:
        server.timeout = 1
        if not webbrowser.open(authorization_url):
            print(
                "Open this URL in your browser:\n{}".format(authorization_url),
                file=sys.stderr,
            )
        deadline = time.time() + CALLBACK_TIMEOUT_SECONDS
        while not result and time.time() < deadline:
            server.handle_request()

    if not result:
        raise RuntimeError("Timed out waiting for Kontist browser authorization.")
    if isinstance(result[0], RuntimeError):
        raise result[0]
    return result[0]


def fetch_confirmed_access_token(client_id: str, client_secret: str) -> str:
    """Use browser OAuth, wait for push-MFA approval, and return the confirmed token."""
    if not client_id.strip() or not client_secret:
        raise ValueError("Kontist client ID and client secret are required.")

    authorization_code = _get_authorization_code(client_id)
    token_response = _request_json(
        TOKEN_PATH,
        "POST",
        payload={
            "grant_type": "authorization_code",
            "code": authorization_code,
            "redirect_uri": REDIRECT_URI,
        },
        client_id=client_id,
        client_secret=client_secret,
    )
    unconfirmed_token = token_response.get("access_token")
    if not isinstance(unconfirmed_token, str) or not unconfirmed_token:
        raise RuntimeError(
            "Kontist did not return an access token for the authorization code."
        )

    challenge = _request_json(
        CHALLENGE_PATH, "POST", payload={}, access_token=unconfirmed_token
    )
    challenge_id = challenge.get("id")
    if not isinstance(challenge_id, str) or not challenge_id:
        raise RuntimeError("Kontist did not return an MFA challenge ID.")
    expires_at = _expires_at_epoch(challenge.get("expiresAt"))

    print("Approve the Kontist login in your Kontist app.", file=sys.stderr)
    while True:
        remaining = expires_at - time.time()
        if remaining <= 0:
            raise RuntimeError("The Kontist MFA challenge expired.")

        status_response = _request_json(
            CHALLENGE_PATH + "/" + urllib.parse.quote(challenge_id, safe=""),
            "GET",
            access_token=unconfirmed_token,
        )
        status = status_response.get("status")
        if status == "DENIED":
            raise RuntimeError("The Kontist MFA challenge was denied.")
        if status == "VERIFIED":
            break
        if status != "PENDING":
            raise RuntimeError("Kontist returned an unknown MFA challenge status.")
        time.sleep(min(POLL_INTERVAL_SECONDS, remaining))

    confirmed_response = _request_json(
        CHALLENGE_PATH + "/" + urllib.parse.quote(challenge_id, safe="") + "/token",
        "POST",
        payload={},
        access_token=unconfirmed_token,
    )
    confirmed_token = confirmed_response.get("token")
    if not isinstance(confirmed_token, str) or not confirmed_token:
        raise RuntimeError("Kontist did not return a confirmed access token.")
    return confirmed_token


def main() -> int:
    client_id = os.environ.get("KONTIST_CLIENT_ID", "")
    client_secret = os.environ.get("KONTIST_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        print(
            "Set KONTIST_CLIENT_ID and KONTIST_CLIENT_SECRET first.",
            file=sys.stderr,
        )
        return 1

    try:
        token = fetch_confirmed_access_token(client_id, client_secret)
    except (RuntimeError, ValueError) as error:
        print("Error: {}".format(error), file=sys.stderr)
        return 1

    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
