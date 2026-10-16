"""Fetch Kontist's spendable balance after VAT and tax calculations ("Meins")."""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

API_URL = "https://api.kontist.com/api/graphql"
MEINS_BALANCE_QUERY = """
query GetMeinsBalance {
  viewer {
    mainAccount {
      stats {
        yours
      }
    }
  }
}
"""


def fetch_yours_balance(access_token: str) -> Any:
    """Return the API's spendable balance after tax and VAT calculations."""
    if not access_token.strip():
        raise ValueError("A non-empty Kontist access token is required.")

    payload = json.dumps({"query": MEINS_BALANCE_QUERY}).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"Kontist API returned HTTP {error.code} ({error.reason})."
        ) from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not connect to the Kontist API: {error.reason}") from error

    errors = result.get("errors")
    if errors:
        messages = "; ".join(
            item.get("message", "Unknown GraphQL error") for item in errors
        )
        raise RuntimeError(f"Kontist GraphQL request failed: {messages}")

    main_account = result.get("data", {}).get("viewer", {}).get("mainAccount")
    stats = main_account.get("stats") if isinstance(main_account, dict) else None
    if not isinstance(stats, dict) or "yours" not in stats:
        raise RuntimeError("Kontist did not return the spendable balance (stats.yours).")
    return stats["yours"]


def main() -> int:
    access_token = os.environ.get("KONTIST_ACCESS_TOKEN", "")
    try:
        balance = fetch_yours_balance(access_token)
    except (RuntimeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(balance))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
