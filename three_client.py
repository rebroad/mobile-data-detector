#!/usr/bin/env python3
"""
Three Mobile Client
External script for interacting with Three Mobile website and API
Accepts SSID argument for username/password configuration
"""

import time
import json
import logging
import os
import signal
import sys
import sqlite3
import tempfile
import shutil
import requests
from typing import Optional, Dict, Any


def load_config(config_file: str = "/etc/mobile_data_monitor.conf") -> Dict[str, Any]:
    """Load configuration from file"""
    config = {}
    try:
        with open(config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip().lower()] = value.strip().strip('"\'')
    except Exception as e:
        print(f"Warning: Could not load config file {config_file}: {e}")
    return config


def resolve_cookie_db_for_ssid(ssid: str, config: Dict) -> Optional[str]:
    """Return path to cookie DB for SSID based on config mapping, if found."""
    mappings_str = config.get('ssid_cookie_profiles', '')
    if not mappings_str:
        return None

    mappings = [m.strip() for m in mappings_str.split(',') if m.strip()]
    if not mappings:
        return None

    # Build mapping dict
    ssid_to_profile = {}
    for entry in mappings:
        parts = [p.strip() for p in entry.split(':')]
        if len(parts) >= 2:
            ssid_key = parts[0]
            ssid_to_profile[ssid_key] = parts[1:]

    target = None
    for key, profile in ssid_to_profile.items():
        if ssid.lower() == key.lower():
            target = profile
            break

    if not target:
        return None

    if target[0] == 'file' and len(target) >= 2:
        return ':'.join(target[1:])

    # Attempt to resolve standard profile paths
    if target[0] in ('chromium', 'chrome') and len(target) >= 2:
        profile_name = target[1]
        home = os.path.expanduser('~')
        candidates = []
        if target[0] == 'chromium':
            candidates.append(os.path.join(home, '.config', 'chromium', profile_name, 'Cookies'))
            candidates.append(os.path.join(home, 'snap', 'chromium', 'common', 'chromium', profile_name, 'Cookies'))
        else:
            candidates.append(os.path.join(home, '.config', 'google-chrome', profile_name, 'Cookies'))

        for cookie_path in candidates:
            if os.path.exists(cookie_path):
                return cookie_path

    return None


def load_cookie_header_via_helper(cookie_db_path: str) -> Optional[str]:
    """Read cookies directly from Chrome/Chromium SQLite database."""
    try:
        # Copy the cookie DB to a temp location since it might be locked
        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_db:
            shutil.copy2(cookie_db_path, temp_db.name)
            temp_db_path = temp_db.name

        try:
            # Connect to the cookie database
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()

            # Query cookies for three.co.uk domain
            cursor.execute("""
                SELECT name, value, host_key, path, expires_utc, is_secure, is_httponly
                FROM cookies
                WHERE host_key LIKE '%three.co.uk%' OR host_key LIKE '%.three.co.uk%'
            """)

            cookies = []
            for row in cursor.fetchall():
                name, value, host_key, path, expires_utc, is_secure, is_httponly = row
                # Skip expired cookies
                if expires_utc and expires_utc > 0 and expires_utc < (time.time() * 1000000):
                    continue
                cookies.append(f"{name}={value}")

            conn.close()
            return '; '.join(cookies) if cookies else None

        finally:
            # Clean up temp file
            try:
                os.unlink(temp_db_path)
            except:
                pass

    except Exception as e:
        print(f"Error reading cookie database: {e}")
        return None


def get_live_three_cookies(config: Dict) -> Optional[tuple[str, Optional[str]]]:
    """Launch browser for user to manually refresh authentication, then detect success"""

    # Get the SSID to determine which browser profile to use
    ssid = getattr(config, '_current_ssid', None)
    if not ssid:
        print("⚠️ No SSID available for determining browser profile")
        return None

    # Get the cookie database path for this SSID
    cookie_db_path = resolve_cookie_db_for_ssid(ssid, config)
    if not cookie_db_path:
        print(f"⚠️ No cookie database configured for SSID: {ssid}")
        return None

    print(f"🔄 Cookie refresh needed for SSID: {ssid}")
    print(f"📁 Using browser profile: {cookie_db_path}")

    # Determine browser command and profile
    browser_cmd, profile_arg = _get_browser_command_for_profile(cookie_db_path)
    if not browser_cmd:
        print("❌ Could not determine browser command")
        return None

    # Check current authentication status
    print("🔍 Checking current authentication status...")
    if _test_current_cookies(cookie_db_path):
        print("✅ Current cookies are valid - no refresh needed")
        return None  # Use existing cookies

    print("🌐 Launching browser for manual login...")
    print("👤 Please log in to Three Mobile when the browser opens")
    print("🔄 Script will automatically detect when login completes...")

    # Launch browser with Three Mobile login page
    success = _launch_browser_for_login(browser_cmd, profile_arg)
    if not success:
        print("❌ Failed to launch browser")
        return None

    # Monitor cookies and wait for authentication
    print("⏳ Waiting for authentication to complete...")
    success = _wait_for_authentication(cookie_db_path, timeout=300)  # 5 minutes

    if success:
        print("✅ Authentication detected! Using fresh cookies...")
        return None  # Trigger fallback to fresh database cookies
    else:
        print("❌ Authentication timeout or failed")
        return None


def _get_browser_command_for_profile(cookie_db_path: str) -> tuple[Optional[str], Optional[str]]:
    """Determine browser command and profile argument from cookie database path"""
    import shutil

    # Determine if it's a Chromium/Chrome profile
    if 'chromium' in cookie_db_path.lower() or 'chrome' in cookie_db_path.lower():
        # Extract profile directory from cookie path
        # e.g., /home/user/snap/chromium/common/chromium/Default/Cookies -> /home/user/snap/chromium/common/chromium
        if '/Default/Cookies' in cookie_db_path:
            user_data_dir = cookie_db_path.replace('/Default/Cookies', '')
            profile_name = 'Default'
        elif '/Profile ' in cookie_db_path and '/Cookies' in cookie_db_path:
            # e.g., /path/Profile 1/Cookies -> /path, Profile 1
            parts = cookie_db_path.replace('/Cookies', '').split('/')
            profile_name = parts[-1]  # e.g., "Profile 1"
            user_data_dir = '/'.join(parts[:-1])
        else:
            user_data_dir = cookie_db_path.replace('/Cookies', '')
            profile_name = None

        # Check for Chromium browser
        chromium_cmd = None
        for cmd in ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']:
            if shutil.which(cmd):
                chromium_cmd = cmd
                break

        if chromium_cmd:
            if profile_name and profile_name != 'Default':
                return (chromium_cmd, f'--user-data-dir={user_data_dir} --profile-directory={profile_name}')
            else:
                return (chromium_cmd, f'--user-data-dir={user_data_dir}')

    # Add support for Firefox profiles if needed
    # elif 'firefox' in cookie_db_path.lower():
    #     # Firefox profile handling...

    return (None, None)


def _test_current_cookies(cookie_db_path: str) -> bool:
    """Test if current cookies are valid by making a quick API call"""
    try:
        import requests

        # Load current cookies
        cookie_header = load_cookie_header_via_helper(cookie_db_path)
        if not cookie_header:
            return False

        # Quick test API call
        headers = {
            'Cookie': cookie_header,
            'Accept': 'application/json, text/plain, */*',
            'Referer': 'https://www.three.co.uk/customer-logged',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'
        }

        response = requests.get(
            'https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user',
            params={'salesChannel': 'selfService'},
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            # Check if we get an authenticated user (not Anonymous)
            return not data.get('isAnonymous', True)

        return False

    except Exception:
        return False


def _launch_browser_for_login(browser_cmd: str, profile_arg: str) -> bool:
    """Launch browser with Three Mobile login page"""
    try:
        import subprocess

        # Three Mobile login URL
        login_url = "https://www.three.co.uk/login"

        # Build command
        cmd = [browser_cmd, profile_arg, login_url]

        # Launch browser in background
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        return True

    except Exception as e:
        print(f"Error launching browser: {e}")
        return False


def _wait_for_authentication(cookie_db_path: str, timeout: int = 300) -> bool:
    """Monitor cookies and wait for successful authentication"""
    import time

    start_time = time.time()
    check_interval = 5  # Check every 5 seconds

    print(f"⏱️  Monitoring for authentication (timeout: {timeout//60} minutes)...")

    while time.time() - start_time < timeout:
        # Test current cookies
        if _test_current_cookies(cookie_db_path):
            return True

        # Show progress
        elapsed = int(time.time() - start_time)
        print(f"⏳ Waiting... ({elapsed}s elapsed)", end='\r')

        time.sleep(check_interval)

    print()  # New line after progress
    return False


def fetch_three_allowance_via_headless(config: Dict, ssid: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """API-only flow within a headless HTMLSession. No page render.

    Sequence (mirrors HAR):
      1) GET /account (to establish cookies)
      2) GET /rp-server-b2c/authentication/v1/B2C/user?salesChannel=selfService → capture uxfauthorization + customerId
      3) GET /rp-server-b2c/commerce/v1/shoppingCart?salesChannel=selfService → capture subscriptionId
      4) GET /rp-server-b2c/billingcare/customer/{customerId}/unbilled-usage-accumulators?... → allowance JSON
    """
    try:
        from requests_html import HTMLSession
    except ImportError:
        print("requests-html not available")
        return None

    session = HTMLSession()

    # Check if we have credentials configured - if so, use headless browser for fresh cookies
    has_credentials = config.get('three_username') and config.get('three_password')
    used_fresh_login = False

    if has_credentials:
        print("Credentials configured - attempting fresh login via headless browser...")
        # Pass SSID to the cookie function
        config['_current_ssid'] = ssid
        result = get_live_three_cookies(config)
        if result:
            cookie_header, uxf_token = result
            print("✅ Got fresh cookies from headless browser login")
            # Set cookies in main session
            for cookie_str in cookie_header.split('; '):
                if '=' in cookie_str:
                    name, value = cookie_str.split('=', 1)
                    session.cookies.set(name, value, domain='.three.co.uk')

            # Store UXF token if available
            if uxf_token:
                session._cached_uxf_token = uxf_token
                print(f"✅ Transferred UXF token from headless session")

            used_fresh_login = True
        else:
            print("❌ Headless browser login failed, falling back to database cookies...")

    # Fallback: try to get cookies from database if SSID is provided and we haven't used fresh login
    if not used_fresh_login and ssid:
        cookie_db_path = resolve_cookie_db_for_ssid(ssid, config)
        if cookie_db_path:
            print(f"Using cookie database for SSID {ssid}: {cookie_db_path}")
            cookie_header = load_cookie_header_via_helper(cookie_db_path)
            if cookie_header:
                print("✅ Loaded cookies from database")
                # Set cookies in session
                for cookie_str in cookie_header.split('; '):
                    if '=' in cookie_str:
                        name, value = cookie_str.split('=', 1)
                        session.cookies.set(name, value, domain='.three.co.uk')

    # 1) Hit account to establish cookies
    account_url = "https://www.three.co.uk/account"
    try:
        r = session.get(account_url, timeout=10)
        print(f"✅ Connected to Three Mobile (status: {r.status_code})")
        time.sleep(0.5)
    except Exception as e:
        print(f"❌ Cannot connect to Three Mobile: {e}")
        print("This could be due to:")
        print("  - Network connectivity issues")
        print("  - DNS resolution problems")
        print("  - Firewall/proxy blocking the connection")
        return None

    # Headers template
    api_headers = {
        'Accept': 'application/json, text/plain, */*',
        'Referer': 'https://www.three.co.uk/customer-logged',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
        'Accept-Language': 'en-GB,en;q=0.9',
        'Origin': 'https://www.three.co.uk',
        'X-Requested-With': 'XMLHttpRequest',
    }

    # Add UXF token if we got it from headless session
    cached_uxf = getattr(session, '_cached_uxf_token', None)
    if cached_uxf:
        api_headers['uxfauthorization'] = cached_uxf
        print(f"✅ Using cached UXF token in API headers")

    # 2) user → uxfauthorization + customerId
    user_url = 'https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user'
    ur = session.get(user_url, params={'salesChannel': 'selfService'}, headers=api_headers)
    if ur.status_code != 200:
        print(f"User API failed: {ur.status_code}")
        # If we haven't tried fresh login yet, try it now
        if not used_fresh_login:
            print("Attempting to get live cookies through login...")
            config['_current_ssid'] = ssid
            result = get_live_three_cookies(config)
            if result:
                cookie_header, uxf_token = result
                # Set cookies in session and retry
                for cookie_str in cookie_header.split('; '):
                    if '=' in cookie_str:
                        name, value = cookie_str.split('=', 1)
                        session.cookies.set(name, value, domain='.three.co.uk')

                # Store UXF token if available
                if uxf_token:
                    session._cached_uxf_token = uxf_token
                    api_headers['uxfauthorization'] = uxf_token
                    print(f"✅ Added UXF token to API headers")

                ur = session.get(user_url, params={'salesChannel': 'selfService'}, headers=api_headers)
                if ur.status_code != 200:
                    print(f"User API still failed after login: {ur.status_code}")
                    return None
            else:
                return None
        else:
            return None

    # Capture fresh token from headers (this is the important part!)
    uxf = ur.headers.get('uxfauthorization')
    if uxf:
        api_headers['uxfauthorization'] = uxf
        print(f"✅ Got fresh UXF token from user API response: {uxf[:100]}...")

    customer_id: Optional[str] = None
    try:
        ud = ur.json()
        print(f"User API response: {ud}")  # Debug what we're getting
        for key in ('customerId', 'partyId', 'id'):
            val = ud.get(key)
            if isinstance(val, (str, int)) and str(val).isdigit():
                customer_id = str(val)
                print(f"✓ Found customer ID '{customer_id}' from key '{key}'")
                break
    except Exception as e:
        print(f"Error parsing user API response: {e}")

    # 3) shoppingCart → subscriptionId (and maybe customerId)
    if not customer_id:
        print("❌ No customer ID found - cannot proceed with shoppingCart API")
        return None

    shopping_url = 'https://www.three.co.uk/rp-server-b2c/commerce/v1/shoppingCart'
    # Need to include customer ID filter based on HAR file analysis
    shopping_params = {
        'salesChannel': 'selfService',
        'filters': f'customer.id=={customer_id}'
    }
    print(f"Making shoppingCart API call with customer ID: {customer_id}")
    cr = session.get(shopping_url, params=shopping_params, headers=api_headers)
    if cr.status_code != 200:
        print(f"shoppingCart failed: {cr.status_code}")
        print(f"Response headers: {dict(cr.headers)}")
        try:
            print(f"Response body: {cr.text[:500]}")
        except:
            pass
        return None

    subscription_id: Optional[str] = None
    try:
        cd = cr.json()
        if customer_id is None:
            val = cd.get('customerId')
            if isinstance(val, (str, int)) and str(val).isdigit():
                customer_id = str(val)

        def _find_sid(o):
            if isinstance(o, dict):
                v = o.get('subscriptionId')
                if isinstance(v, (str, int)) and str(v).isdigit():
                    return str(v)
                for vv in o.values():
                    r = _find_sid(vv)
                    if r:
                        return r
            if isinstance(o, list):
                for it in o:
                    r = _find_sid(it)
                    if r:
                        return r
            return None

        subscription_id = _find_sid(cd)
    except Exception:
        pass

    if not customer_id or not subscription_id:
        print("Could not determine live customerId/subscriptionId")
        return None

    print(f"✓ Using customer ID: {customer_id}")
    print(f"✓ Using subscription ID: {subscription_id}")

    # 4) allowance
    allowance_url = f"https://www.three.co.uk/rp-server-b2c/billingcare/customer/{customer_id}/unbilled-usage-accumulators"
    params = {
        'usageAccumulatorType': 'allowance',
        'subscriptionId': subscription_id,
        'isPrepay': 'false',
        'pairedMsisdn': '',
        'salesChannel': 'selfService'
    }
    ar = session.get(allowance_url, params=params, headers=api_headers)
    if ar.status_code != 200:
        print(f"Allowance API failed: {ar.status_code}")
        return None

    try:
        return ar.json()
    except Exception:
        return None


def _accumulators_remaining_mb(data: Dict[str, Any]) -> Optional[int]:
    """Convert allowance data to remaining MB"""
    try:
        accs = data.get('accumulators', [])
        total_gb = 0.0
        for acc in accs:
            if acc.get('type') == 'allowance' and acc.get('unitOfMeasurement') == 'gbytes':
                rq = acc.get('remainingQuota')
                try:
                    total_gb += float(rq)
                except (TypeError, ValueError):
                    continue
        # Convert to MB (GiB vs GB ambiguity; follow site which uses GB base10)
        remaining_mb = int(round(total_gb * 1000))
        return remaining_mb
    except Exception:
        return None


if __name__ == "__main__":
    # Accept SSID as optional argument
    ssid = sys.argv[1] if len(sys.argv) > 1 else None

    # Load configuration
    cfg = load_config()

    # Quick connectivity check
    try:
        import socket
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        print("✅ Internet connectivity confirmed")
    except Exception:
        print("❌ No internet connectivity detected")
        print("Please check your network connection and try again")
        try:
            os.write(3, b"-1\n")
        except Exception:
            pass
        raise SystemExit(3)

    # Update credentials based on SSID if provided
    if ssid:
        print(f"Using SSID: {ssid}")

    result = fetch_three_allowance_via_headless(cfg, ssid)
    if not result:
        print("Failed to fetch allowance", flush=True)
        # Still attempt to signal failure on FD 3 with -1
        try:
            os.write(3, b"-1\n")
        except Exception:
            pass
        raise SystemExit(1)

    mb = _accumulators_remaining_mb(result)
    if mb is None:
        print("Could not compute remaining MB", flush=True)
        try:
            os.write(3, b"-1\n")
        except Exception:
            pass
        raise SystemExit(2)

    # Log summary to stdout
    print(f"✅ Successfully fetched allowance data")
    print(f"Remaining (MB): {mb}", flush=True)

    # Write machine-readable value to FD 3
    try:
        os.write(3, f"{mb}\n".encode())
    except Exception:
        # Fallback: also print to stdout if FD 3 not available
        print(mb)
