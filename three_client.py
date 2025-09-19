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
    ssid = config.get('_current_ssid')
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
            # Use a separate window but same profile to avoid database conflicts
            if profile_name and profile_name != 'Default':
                return (chromium_cmd, f'--user-data-dir={user_data_dir} --profile-directory={profile_name} --new-window')
            else:
                return (chromium_cmd, f'--user-data-dir={user_data_dir} --new-window')

    # Add support for Firefox profiles if needed
    # elif 'firefox' in cookie_db_path.lower():
    #     # Firefox profile handling...

    return (None, None)


def _get_live_cookies_from_chrome() -> Optional[str]:
    """Get live cookies by copying the cookie database to avoid lock issues"""
    try:
        import tempfile
        import shutil
        import os

        print("  🔍 Debug: Attempting to read cookies by copying database...")

        # Get the main Chromium cookie database path
        cookie_db_path = "/home/rebroad/snap/chromium/common/chromium/Default/Cookies"

        if not os.path.exists(cookie_db_path):
            print(f"  ❌ Debug: Cookie database not found: {cookie_db_path}")
            return None

        # Create a temporary copy of the cookie database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
            temp_db_path = temp_db.name

        try:
            # Copy the database file
            print("  🔄 Debug: Copying cookie database to temporary location...")
            shutil.copy2(cookie_db_path, temp_db_path)

            # Now read from the copy (no lock issues)
            print("  📖 Debug: Reading cookies from temporary database copy...")
            cookie_header = load_cookie_header_via_helper(temp_db_path)

            if cookie_header:
                print(f"  ✅ Debug: Successfully read cookies from database copy")
                return cookie_header
            else:
                print("  ❌ Debug: No cookies found in database copy")
                return None

        except Exception as e:
            print(f"  ❌ Debug: Failed to copy/read cookie database: {e}")
            return None
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_db_path)
            except:
                pass

    except Exception as e:
        print(f"  ❌ Debug: Cookie database copy failed: {e}")
        return None


def _perform_oauth_login(session, config: Dict) -> bool:
    """Perform OAuth login flow using pure API calls (following HAR patterns exactly)"""
    try:
        import urllib.parse
        import hashlib
        import base64
        import secrets
        import re

        username = config.get('three_username')
        password = config.get('three_password')

        if not username or not password:
            print("  ❌ API OAuth: No credentials configured")
            return False

        print("  🔍 API OAuth: Starting HAR-pattern authentication flow...")

        # Set proper headers to mimic browser exactly (from HAR)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        })

        # Step 1: Visit Three login page first (as seen in HAR)
        print("  🔍 API OAuth: Visiting Three login page...")
        login_page = session.get('https://www.three.co.uk/login')

        if login_page.status_code != 200:
            print(f"  ❌ API OAuth: Login page failed: {login_page.status_code}")
            return False

        # Step 2: Generate PKCE parameters (as seen in HAR)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode('utf-8')).digest()
        ).decode('utf-8').rstrip('=')

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        # Step 3: Start OAuth flow (exact parameters from HAR)
        auth_params = {
            'client_id': 'my3account',
            'redirect_uri': 'https://www.three.co.uk/customer-logged',
            'response_type': 'code',
            'scope': 'openid profile',
            'state': state,
            'nonce': nonce,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'audience': 'https://three-eu.eu.auth0.com/api/v2/'
        }

        auth_url = 'https://three-eu.eu.auth0.com/authorize?' + urllib.parse.urlencode(auth_params)

        print("  🔍 API OAuth: Starting Auth0 authorization...")
        auth_response = session.get(auth_url, headers={
            'Referer': 'https://www.three.co.uk/',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site'
        })

        if auth_response.status_code != 200:
            print(f"  ❌ API OAuth: Auth0 authorization failed: {auth_response.status_code}")
            return False

        # Step 4: Parse login form (check for anti-automation measures)
        print("  🔍 API OAuth: Parsing Auth0 login form...")

        if 'captcha' in auth_response.text.lower() or 'recaptcha' in auth_response.text.lower():
            print("  ⚠️ API OAuth: CAPTCHA detected - need browser fallback")
            return False

        if 'blocked' in auth_response.text.lower() or 'suspicious' in auth_response.text.lower():
            print("  ⚠️ API OAuth: Bot detection triggered - need browser fallback")
            return False

        # Extract form action and state
        form_match = re.search(r'<form[^>]+action="([^"]+)"[^>]*>', auth_response.text)
        if not form_match:
            print("  ❌ API OAuth: No login form found")
            return False

        form_action = form_match.group(1)

        # Extract all hidden fields and CSRF tokens
        hidden_fields = {}
        for match in re.finditer(r'<input[^>]+type="hidden"[^>]+name="([^"]+)"[^>]+value="([^"]*)"', auth_response.text):
            hidden_fields[match.group(1)] = match.group(2)

        print(f"  🔍 API OAuth: Found {len(hidden_fields)} form fields")

        # Step 5: Submit credentials with exact headers from HAR
        print("  🔍 API OAuth: Submitting login credentials...")

        login_data = {
            'username': username,
            'password': password,
            'action': 'default',
            **hidden_fields
        }

        login_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://three-eu.eu.auth0.com',
            'Referer': auth_response.url,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1'
        }

        login_response = session.post(
            f"https://three-eu.eu.auth0.com{form_action}",
            data=login_data,
            headers=login_headers,
            allow_redirects=True
        )

        # Step 6: Check for successful authentication
        if login_response.status_code == 200:
            if 'customer-logged' in login_response.url and 'code=' in login_response.url:
                print("  ✅ API OAuth: Authentication successful!")
                return True
            elif 'error' in login_response.url:
                print("  ❌ API OAuth: Login credentials rejected")
                return False
            elif 'mfa' in login_response.text.lower() or '2fa' in login_response.text.lower():
                print("  ⚠️ API OAuth: 2FA required - need browser fallback")
                return False
            else:
                print("  ⚠️ API OAuth: Unexpected response - need browser fallback")
                return False
        else:
            print(f"  ❌ API OAuth: Login request failed: {login_response.status_code}")
            return False

    except Exception as e:
        print(f"  ❌ API OAuth: Failed with error: {e}")
        return False


def _perform_oauth_login_with_render(session, config: Dict) -> bool:
    """Fallback OAuth using headless browser rendering"""
    try:
        print("  🔍 Browser OAuth: Using headless browser rendering...")

        # Use requests-html render() for JavaScript execution
        username = config.get('three_username')
        password = config.get('three_password')

        # Visit login page and render JavaScript
        login_page = session.get('https://www.three.co.uk/login')
        login_page.html.render(timeout=20)

        # Use the browser to handle the complete OAuth flow
        print("  🔍 Browser OAuth: JavaScript rendering complete")

        # This would need more implementation, but serves as the fallback
        # For now, return False to indicate it needs implementation
        print("  ⚠️ Browser OAuth: Not yet implemented - needs JS automation")
        return False

    except Exception as e:
        print(f"  ❌ Browser OAuth: Failed with error: {e}")
        return False


def _test_current_cookies(cookie_db_path: str) -> bool:
    """Test if current cookies are valid by making a quick API call"""
    try:
        import requests

        # First try to get live cookies from Chrome DevTools
        print("  🔍 Debug: Attempting to get live cookies from Chrome...")
        live_cookies = _get_live_cookies_from_chrome()
        if live_cookies:
            print("  ✅ Debug: Using live cookies from Chrome DevTools")
            cookie_header = live_cookies
        else:
            # Fallback to database cookies (may be locked/empty)
            print("  ⚠️ Debug: Chrome DevTools failed, falling back to database cookies")
            cookie_header = load_cookie_header_via_helper(cookie_db_path)

        if not cookie_header:
            print("  🔍 Debug: No cookies found in database")
            return False

        print(f"  🔍 Debug: Found {len(cookie_header.split(';'))} cookies")

        # Check for key authentication cookies
        key_cookies = ['WIRELESS_SECURITY_TOKEN', 'auth0', 'auth0_compat']
        found_auth_cookies = []
        for cookie in key_cookies:
            if f'{cookie}=' in cookie_header:
                found_auth_cookies.append(cookie)

        print(f"  🔍 Debug: Found auth cookies: {found_auth_cookies}")

        # Check cookie freshness - get modification time of cookie database
        import os
        try:
            db_mtime = os.path.getmtime(cookie_db_path)
            import time
            current_time = time.time()
            age_minutes = (current_time - db_mtime) / 60
            print(f"  🔍 Debug: Cookie database last modified {age_minutes:.1f} minutes ago")
        except Exception as e:
            print(f"  🔍 Debug: Could not check cookie database age: {e}")

        # Check if Chrome is running and locking the database
        import subprocess
        try:
            result = subprocess.run(['pgrep', '-f', 'chromium|chrome'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"  🔍 Debug: Chrome/Chromium is running (PIDs: {result.stdout.strip().replace(chr(10), ', ')}) - may cause database lock")
        except Exception:
            pass

        # Show a sample of key cookies with their values (truncated)
        key_cookie_values = {}
        for cookie in key_cookies:
            for cookie_part in cookie_header.split(';'):
                if cookie_part.strip().startswith(f'{cookie}='):
                    value = cookie_part.split('=', 1)[1].strip()
                    key_cookie_values[cookie] = value[:20] + '...' if len(value) > 20 else value
                    break
        print(f"  🔍 Debug: Key cookie values: {key_cookie_values}")

        # Quick test API call
        headers = {
            'Cookie': cookie_header,
            'Accept': 'application/json, text/plain, */*',
            'Referer': 'https://www.three.co.uk/customer-logged',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'
        }

        print(f"  🔍 Debug: Testing API call to /B2C/user...")
        response = requests.get(
            'https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user',
            params={'salesChannel': 'selfService'},
            headers=headers,
            timeout=10
        )

        print(f"  🔍 Debug: API response status: {response.status_code}")

        # Also test account page access
        print(f"  🔍 Debug: Testing account page access...")
        try:
            account_response = requests.get(
                'https://www.three.co.uk/account',
                headers=headers,
                timeout=10,
                allow_redirects=False
            )
            print(f"  🔍 Debug: Account page status: {account_response.status_code}")
            if account_response.status_code in [301, 302, 303, 307, 308]:
                redirect_location = account_response.headers.get('Location', 'No location header')
                print(f"  🔍 Debug: Account page redirects to: {redirect_location}")
        except Exception as e:
            print(f"  🔍 Debug: Account page test failed: {e}")

        if response.status_code == 200:
            data = response.json()
            user_id = data.get('userId', 'Unknown')
            is_anonymous = data.get('isAnonymous', True)
            print(f"  🔍 Debug: User ID: {user_id}, Anonymous: {is_anonymous}")

            # Check if we get an authenticated user (not Anonymous)
            is_valid = not is_anonymous
            print(f"  🔍 Debug: Cookies valid: {is_valid}")
            return is_valid
        else:
            print(f"  🔍 Debug: API call failed with status {response.status_code}")
            return False

    except Exception as e:
        print(f"  🔍 Debug: Exception during cookie test: {e}")
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
    check_interval = 1  # Check every 1 second for responsive monitoring
    last_check_time = 0

    print(f"⏱️  Monitoring for authentication (timeout: {timeout//60} minutes)...")
    print("💡 Please log in to Three Mobile in the browser that opened")
    print("🔄 Checking cookies every second for authentication completion...")
    print()

    while time.time() - start_time < timeout:
        current_time = time.time()
        elapsed = int(current_time - start_time)

        # Only test cookies every second to avoid spam
        if current_time - last_check_time >= check_interval:
            print(f"⏳ [{elapsed:03d}s] Testing cookies...", end='', flush=True)

            # Test current cookies with detailed output
            if _test_current_cookies(cookie_db_path):
                print(" ✅ AUTHENTICATED!")
                print("🎉 Fresh authentication detected! Continuing...")
                return True
            else:
                print(" ❌ Still waiting for login...")

            last_check_time = current_time

        time.sleep(0.1)  # Small sleep to prevent CPU spinning

    print(f"\n❌ Timeout after {timeout}s - authentication not detected")
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

    # Step 1: Try to get live cookies from Chrome DevTools first, then fallback to database
    used_fresh_login = False
    if ssid:
        cookie_db_path = resolve_cookie_db_for_ssid(ssid, config)
        if cookie_db_path:
            print(f"Using cookie database for SSID {ssid}: {cookie_db_path}")

            # Test cookies (this will try Chrome DevTools first, then database)
            print("🔍 Testing current authentication...")
            if _test_current_cookies(cookie_db_path):
                print("✅ Valid authentication found - proceeding")

                # Try to get live cookies from Chrome first
                live_cookies = _get_live_cookies_from_chrome()
                if live_cookies:
                    print("✅ Using live cookies from Chrome DevTools")
                    cookie_header = live_cookies
                else:
                    print("⚠️ Using database cookies")
                    cookie_header = load_cookie_header_via_helper(cookie_db_path)

                if cookie_header:
                    # Set cookies in session
                    for cookie_str in cookie_header.split('; '):
                        if '=' in cookie_str:
                            name, value = cookie_str.split('=', 1)
                            session.cookies.set(name, value, domain='.three.co.uk')
                else:
                    print("❌ Current cookies are stale or empty - need fresh authentication")
                    # Use OAuth flow as fallback
                    has_credentials = config.get('three_username') and config.get('three_password')
                    if has_credentials:
                        print("🔄 Attempting API-based OAuth login (following HAR patterns)...")
                        oauth_result = _perform_oauth_login(session, config)
                        if oauth_result:
                            print("✅ OAuth login successful")
                            used_fresh_login = True
                        else:
                            print("❌ API OAuth failed - trying headless browser fallback...")
                            # Fallback to headless browser rendering
                            browser_result = _perform_oauth_login_with_render(session, config)
                            if browser_result:
                                print("✅ Browser OAuth login successful")
                                used_fresh_login = True
                            else:
                                print("❌ All OAuth methods failed")
                    else:
                        print("⚠️ No credentials configured and cookies empty")
                        print("💡 Either:")
                        print("💡   1. Log into Three Mobile in your browser, or")
                        print("💡   2. Configure three_username/three_password in config")
                        return None
            else:
                print("❌ No cookies found in database")

    # 2) Hit account to establish cookies
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
