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
from typing import Optional, Dict, Any, List


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


def _log_nav(prefix: str, url: str) -> None:
    """Compact navigation logger that highlights the current domain.

    Example output:
      🔍 Step: https://www.three.co.uk/account  (host=www.three.co.uk, on_auth=False, on_www=True)
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url or "")
        host = parsed.netloc or "(no-host)"
        on_auth = "auth.three.co.uk" in host
        on_www = "www.three.co.uk" in host
        print(f"  🔍 {prefix}: {url}  (host={host}, on_auth={on_auth}, on_www={on_www})")
    except Exception:
        print(f"  🔍 {prefix}: {url}")


# --- Lightweight opt-in HTTP tracing for request/response flow comparison ---
_THREE_TRACE_PATH = os.environ.get('THREE_TRACE_PATH') or '/tmp/three_trace.jsonl'
if _THREE_TRACE_PATH:
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(_THREE_TRACE_PATH), exist_ok=True)
    except Exception:
        pass

    _ORIG_REQUEST = requests.Session.request

    def _trace_write(record: Dict[str, Any]) -> None:
        try:
            with open(_THREE_TRACE_PATH, 'a', encoding='utf-8') as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            # Tracing must never break primary logic
            pass

    def _traced_request(self, method, url, **kwargs):  # type: ignore[override]
        start_ts = time.time()
        req_headers = {}
        try:
            if 'headers' in kwargs and isinstance(kwargs['headers'], dict):
                req_headers = {str(k).lower(): str(v) for k, v in kwargs['headers'].items()}
        except Exception:
            req_headers = {}

        try:
            resp = _ORIG_REQUEST(self, method, url, **kwargs)
        except Exception as e:
            _trace_write({
                'ts': start_ts,
                'event': 'request_error',
                'method': method,
                'url': url,
                'error': repr(e),
                'request_headers': req_headers,
            })
            raise

        try:
            _trace_write({
                'ts': start_ts,
                'event': 'response',
                'method': method,
                'url': url,
                'final_url': getattr(resp, 'url', url),
                'status': getattr(resp, 'status_code', None),
                'is_redirect': bool(getattr(resp, 'is_redirect', False)),
                'history': [
                    {
                        'url': getattr(h, 'url', ''),
                        'status': getattr(h, 'status_code', None)
                    } for h in getattr(resp, 'history', [])
                ],
                'request_headers': req_headers,
                'response_headers': {k.lower(): v for k, v in getattr(resp, 'headers', {}).items()}
            })
        except Exception:
            pass

        return resp

    # Monkey-patch requests to enable transparent tracing
    requests.Session.request = _traced_request  # type: ignore[assignment]
    print(f"🔍 HTTP tracing enabled: {_THREE_TRACE_PATH}")

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
            except Exception:
                pass

    except Exception as e:
        print(f"Error reading cookies: {e}")
        return None

def load_cookies_with_domains(cookie_db_path: str) -> List[Dict[str, str]]:
    """Read cookies with their domains from Chrome/Chromium SQLite database."""
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
                cookies.append({
                    'name': name,
                    'value': value,
                    'domain': host_key,
                    'path': path
                })

            conn.close()
            return cookies

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
            cookies_with_domains = load_cookies_with_domains(temp_db_path)

            if cookies_with_domains:
                print(f"  ✅ Debug: Successfully read cookies from database copy")
                # Convert to cookie header format for compatibility
                cookie_header = '; '.join([f"{c['name']}={c['value']}" for c in cookies_with_domains])
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

        # Step 1: Start OAuth flow from Three's login page (as seen in HAR)
        print("  🔍 API OAuth: Starting from Three login page...")
        print("  🔍 API OAuth: Requesting https://www.three.co.uk/login")

        # Disable automatic redirects to see the redirect chain
        session.max_redirects = 0
        try:
            login_response = session.get('https://www.three.co.uk/login', allow_redirects=False)
            print(f"  🔍 API OAuth: Initial response: {login_response.status_code}")
            _log_nav("API OAuth initial URL", login_response.url)

            if login_response.status_code in [301, 302, 303, 307, 308]:
                redirect_url = login_response.headers.get('Location', 'Unknown')
                print(f"  🔍 API OAuth: Redirected to: {redirect_url}")
                _log_nav("API OAuth redirect target", redirect_url)

                # Follow the redirect
                session.max_redirects = 30  # Reset to normal
                login_page = session.get('https://www.three.co.uk/login')
                _log_nav("API OAuth final URL after redirects", login_page.url)
            else:
                login_page = login_response

        except Exception as e:
            print(f"  🔍 API OAuth: Redirect tracking failed: {e}")
            # Fallback to normal request
            session.max_redirects = 30
            login_page = session.get('https://www.three.co.uk/login')
            _log_nav("API OAuth final URL (fallback)", login_page.url)

        if login_page.status_code != 200:
            print(f"  ❌ API OAuth: Login page failed: {login_page.status_code}")
            return False

        # Step 2: Look for the login button/link that starts OAuth flow
        import re

        # Find the OAuth authorization URL in the login page
        auth_links = []

        # Look for various Auth0/OAuth patterns
        patterns = [
            r'href="(https://auth\.three\.co\.uk[^"]*)"',
            r'href="([^"]*auth\.three\.co\.uk[^"]*)"',
            r'action="([^"]*auth[^"]*)"',
            r'data-url="([^"]*auth[^"]*)"',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, login_page.text)
            auth_links.extend(matches)

        if not auth_links:
            print("  ❌ API OAuth: No Auth0 authorization link found on login page")
            return False

        # Use the first Auth0 link found
        auth_url = auth_links[0]
        print(f"  🔍 API OAuth: Found OAuth URL: {auth_url[:80]}...")

        # Step 3: Follow the OAuth authorization link (this should give us the login form with state)
        print("  🔍 API OAuth: Following OAuth authorization link...")

        auth_response = session.get(auth_url, headers={
            'Referer': 'https://www.three.co.uk/',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site'
        })

        if auth_response.status_code != 200:
            print(f"  ❌ API OAuth: OAuth authorization failed: {auth_response.status_code}")
            return False

        # Step 4: Extract state parameter from URL or form (from HAR)
        print("  🔍 API OAuth: Extracting login form parameters...")

        if 'captcha' in auth_response.text.lower() or 'recaptcha' in auth_response.text.lower():
            print("  ⚠️ API OAuth: CAPTCHA detected - need browser fallback")
            return False

        if 'blocked' in auth_response.text.lower() or 'suspicious' in auth_response.text.lower():
            print("  ⚠️ API OAuth: Bot detection triggered - need browser fallback")
            return False

        # Extract state from URL (as seen in HAR file)
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(auth_response.url)
        query_params = parse_qs(parsed_url.query)
        state_param = query_params.get('state', [None])[0]

        if not state_param:
            print("  ❌ API OAuth: No state parameter found in login URL")
            return False

        print(f"  🔍 API OAuth: Extracted state parameter: {state_param[:20]}...")

        # Step 5: Submit credentials exactly as shown in HAR
        print("  🔍 API OAuth: Submitting login credentials...")

        # From HAR: POST data format
        login_data = {
            'state': state_param,
            'username': username,
            'password': password
        }

        # From HAR: exact headers
        login_headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://auth.three.co.uk',
            'Referer': auth_response.url,
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1'
        }

        # From HAR: POST to the same URL with state parameter
        login_response = session.post(
            auth_response.url,  # POST to same URL as GET
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
    """OAuth using headless browser with JavaScript automation"""
    try:
        print("  🔍 Browser OAuth: Using headless browser with JavaScript...")

        username = config.get('three_username')
        password = config.get('three_password')

        if not username or not password:
            print("  ❌ Browser OAuth: No credentials configured")
            return False

        # Step 1: Visit login page and render JavaScript
        print("  🔍 Browser OAuth: Loading Three login page...")
        print("  🔍 Browser OAuth: Requesting https://www.three.co.uk/login")

        login_page = session.get('https://www.three.co.uk/login')
        _log_nav("Browser OAuth initial URL", login_page.url)

        print("  🔍 Browser OAuth: Rendering JavaScript (this may take a moment)...")
        login_page.html.render(timeout=30, wait=3)  # Wait for JS to load

        _log_nav("Browser OAuth after initial JS", login_page.url)

        # Check if we're redirected to Auth0 domain
        if 'auth.three.co.uk' not in login_page.url:
            print("  🔍 Browser OAuth: Not yet on Auth0 domain, waiting for additional redirects...")
            # Wait longer for OAuth redirects to complete
            login_page.html.render(timeout=30, wait=5)
            _log_nav("Browser OAuth after waiting for redirects", login_page.url)

        # Show if JavaScript caused additional redirects
        if 'login' not in login_page.url:
            _log_nav("Browser OAuth JS redirected to", login_page.url)

        # Test if we're actually authenticated by making an API call
        print("  🔍 Browser OAuth: Testing authentication with API call...")

        # Copy cookies from the rendered page
        for cookie in login_page.cookies:
            session.cookies.set(cookie.name, cookie.value, domain=cookie.domain or '.three.co.uk')

        # Test authentication with the B2C user API
        try:
            test_response = session.get('https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user?salesChannel=selfService', timeout=10)
            if test_response.status_code == 200:
                user_data = test_response.json()
                user_id = user_data.get('userId', 'Unknown')
                is_anonymous = user_data.get('isAnonymous', True)

                if not is_anonymous and user_id != 'Anonymous':
                    print(f"  🎉 Browser OAuth: Already authenticated! User ID: {user_id}")
                    return True
                else:
                    print(f"  🔍 Browser OAuth: Not authenticated (User: {user_id}, Anonymous: {is_anonymous})")
            else:
                print(f"  🔍 Browser OAuth: API test failed: {test_response.status_code}")
        except Exception as e:
            print(f"  🔍 Browser OAuth: API test error: {e}")

        # Step 2: Ensure we are on Auth0 before attempting to submit credentials
        print("  🔍 Browser OAuth: Preparing to locate login form...")
        _log_nav("Browser OAuth current page", login_page.url)
        from urllib.parse import urlparse
        host_now = (urlparse(login_page.url).netloc or "").lower()
        on_auth_now = 'auth.three.co.uk' in host_now
        print(f"  🔍 Browser OAuth: Auth0 domain reached: {on_auth_now} (host={host_now})")

        if not on_auth_now:
            print("  🔍 Browser OAuth: Still on www.three.co.uk after JS; will not click or submit. Waiting for site-driven redirect to auth.three.co.uk is required.")
            # For diagnostics only: enumerate visible CTA-like elements that might initiate Auth0
            try:
                js_list_ctas = r"""
                (function(){
                  function textOf(el){
                    try{ return (el.innerText||el.textContent||'').trim().replace(/\s+/g,' ').slice(0,120);}catch(e){return ''}
                  }
                  function attrs(el){
                    var a={};
                    try{ a.href=el.getAttribute('href')||''; }catch(e){}
                    try{ a.role=el.getAttribute('role')||''; }catch(e){}
                    try{ a.id=el.id||''; }catch(e){}
                    try{ a.class=(el.className||'').toString(); }catch(e){}
                    return a;
                  }
                  var candidates=[];
                  var selectors = [
                    'a[href*="auth.three.co.uk"]',
                    'a[href*="/u/login"]',
                    'a[href*="/authorize"]',
                    'a[href*="/oauth"]',
                    'button', 'a', 'div[role="button"]'
                  ];
                  var seen=new Set();
                  for (var i=0;i<selectors.length;i++){
                    var els = document.querySelectorAll(selectors[i]);
                    for (var j=0;j<els.length;j++){
                      var el=els[j];
                      var info=attrs(el);
                      var txt=textOf(el).toLowerCase();
                      var looksLogin = /log in|login|sign in|my account|account|customer/i.test(txt);
                      var looksAuth = (info.href||'').indexOf('auth.three.co.uk')>=0 || /\/(u\/login|authorize|oauth)/.test(info.href||'');
                      if (looksLogin || looksAuth){
                        var key=(info.href||'')+"|"+txt;
                        if (!seen.has(key)){
                          seen.add(key);
                          candidates.push({text: txt.slice(0,120), href: info.href||'', role: info.role||'', id: info.id||'', class: info.class||''});
                          if (candidates.length>=10) break;
                        }
                      }
                    }
                    if (candidates.length>=10) break;
                  }
                  return JSON.stringify(candidates);
                })();
                """
                result = login_page.html.render(script=js_list_ctas, timeout=20)
                # requests-html returns the page HTML after render; we need to fetch the JS evaluation result via console? Fallback: run a second lightweight eval
                try:
                    from pyppeteer.errors import NetworkError  # type: ignore
                except Exception:
                    NetworkError = Exception
                try:
                    # Try again with shorter timeout to capture evaluate return
                    result = login_page.html.render(script=js_list_ctas, timeout=5)
                except NetworkError:
                    pass
                # As requests-html doesn't expose direct return, re-run by writing to window.__CTAS and then read via a separate evaluate
                js_store = js_list_ctas.replace('return JSON.stringify(candidates);','window.__CTAS = JSON.stringify(candidates); return "ok";')
                try:
                    _ = login_page.html.render(script=js_store, timeout=10)
                    js_read = '(() => { try { return window.__CTAS || "[]" } catch(e){ return "[]" } })();'
                    ctas_json = login_page.html.render(script=js_read, timeout=5)
                except Exception:
                    ctas_json = '[]'
                try:
                    ctas = json.loads(ctas_json) if isinstance(ctas_json, str) else []
                except Exception:
                    ctas = []
                if ctas:
                    print("  🔍 Browser OAuth: Detected possible login CTAs on current page (diagnostic only):")
                    for idx, c in enumerate(ctas, 1):
                        text = (c.get('text') or '')
                        href = (c.get('href') or '')
                        role = (c.get('role') or '')
                        cid = (c.get('id') or '')
                        cls = (c.get('class') or '')
                        print(f"    [{idx}] text='{text}' href='{href}' role='{role}' id='{cid}' class='{cls}'")
                else:
                    print("  🔍 Browser OAuth: No obvious login CTAs detected on current page")
            except Exception as e:
                print(f"  ⚠️ Browser OAuth: CTA diagnostics failed: {e}")

        if not on_auth_now:
            print("  ❌ Browser OAuth: Still not on Auth0 login page; will not submit credentials on www.three.co.uk")
            return False

        # Try to find username/password fields with broader selectors
        username_selectors = [
            'input[type="email"]',
            'input[type="text"][name*="username"]',
            'input[type="text"][name*="email"]',
            'input[name*="username"]',
            'input[name*="email"]',
            'input[placeholder*="email"]',
            'input[placeholder*="username"]',
            '#username', '#email', '#user', '#login'
        ]

        password_selectors = [
            'input[type="password"]',
            'input[name*="password"]',
            'input[placeholder*="password"]',
            '#password', '#pass'
        ]

        username_input = None
        for selector in username_selectors:
            username_input = login_page.html.find(selector, first=True)
            if username_input:
                print(f"  🔍 Browser OAuth: Found username field with: {selector}")
                break

        password_input = None
        for selector in password_selectors:
            password_input = login_page.html.find(selector, first=True)
            if password_input:
                print(f"  🔍 Browser OAuth: Found password field with: {selector}")
                break

        if not username_input or not password_input:
            print("  ❌ Browser OAuth: Login form not found after JS rendering")
            print(f"  🔍 Debug: Username field found: {bool(username_input)}")
            print(f"  🔍 Debug: Password field found: {bool(password_input)}")
            print(f"  🔍 Debug: Page title: {login_page.html.find('title', first=True)}")

            # Show some page content for debugging
            page_text = login_page.html.text[:500] if login_page.html.text else "No text content"
            print(f"  🔍 Debug: Page content sample: {page_text[:200]}...")
            return False

        print(f"  ✅ Browser OAuth: Login form found (host={host_now}, on_auth={on_auth_now})!")

        # Step 3: Fill in the form using JavaScript
        print(f"  🔍 Browser OAuth: Filling and submitting form on host={host_now} (on_auth={on_auth_now})...")

        # Use evaluate() to fill the form with JavaScript
        js_code = f"""
        // Find and fill username field
        var usernameField = document.querySelector('input[type="email"], input[name*="username"], input[name*="email"], #username, #email');
        if (usernameField) {{
            usernameField.value = '{username}';
            usernameField.dispatchEvent(new Event('input', {{ bubbles: true }}));
            usernameField.dispatchEvent(new Event('change', {{ bubbles: true }}));
        }}

        // Find and fill password field
        var passwordField = document.querySelector('input[type="password"], input[name*="password"], #password');
        if (passwordField) {{
            passwordField.value = '{password}';
            passwordField.dispatchEvent(new Event('input', {{ bubbles: true }}));
            passwordField.dispatchEvent(new Event('change', {{ bubbles: true }}));
        }}

        // Submit the form
        var submitButton = document.querySelector('button[type="submit"], input[type="submit"]');
        if (!submitButton) {{
            // Look for buttons with login text
            var buttons = document.querySelectorAll('button');
            for (var i = 0; i < buttons.length; i++) {{
                var button = buttons[i];
                var text = button.textContent.toLowerCase();
                if (text.includes('log in') || text.includes('sign in') || text.includes('login')) {{
                    submitButton = button;
                    break;
                }}
            }}
        }}

        if (submitButton) {{
            submitButton.click();
        }} else {{
            // Try form submit
            var form = document.querySelector('form');
            if (form) form.submit();
        }}

        // Return success
        'form_submitted';
        """

        try:
            result = login_page.html.render(script=js_code, timeout=20)
            print("  🔍 Browser OAuth: Form submission attempted")

            # Wait for potential redirects and check final URL
            import time
            time.sleep(5)

            final_url = login_page.url
            _log_nav("Browser OAuth final URL after login", final_url)

            # Copy any new cookies back to the main session
            for cookie in login_page.cookies:
                session.cookies.set(cookie.name, cookie.value, domain=cookie.domain or '.three.co.uk')

            # Test authentication with API call instead of assuming from URL
            print("  🔍 Browser OAuth: Testing login success with API call...")
            try:
                test_response = session.get('https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user?salesChannel=selfService', timeout=10)
                if test_response.status_code == 200:
                    user_data = test_response.json()
                    user_id = user_data.get('userId', 'Unknown')
                    is_anonymous = user_data.get('isAnonymous', True)

                    print(f"  🔍 Browser OAuth: API test result - User: {user_id}, Anonymous: {is_anonymous}")

                    if not is_anonymous and user_id != 'Anonymous':
                        print(f"  ✅ Browser OAuth: Login successful! Authenticated as: {user_id}")
                        return True
                    else:
                        print(f"  ❌ Browser OAuth: Login failed - still anonymous (User: {user_id})")
                        return False
                else:
                    print(f"  ❌ Browser OAuth: API test failed with status: {test_response.status_code}")
                    return False
            except Exception as e:
                print(f"  ❌ Browser OAuth: API test error: {e}")
                return False

        except Exception as e:
            print(f"  ❌ Browser OAuth: JavaScript execution failed: {e}")
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
                    # Load cookies with their correct domains
                    cookies_with_domains = load_cookies_with_domains(cookie_db_path)
                    for cookie in cookies_with_domains:
                        session.cookies.set(
                            cookie['name'],
                            cookie['value'],
                            domain=cookie['domain'],
                            path=cookie['path']
                        )
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
                            return None
                else:
                    print("⚠️ No credentials configured and cookies invalid")
                    print("💡 Either:")
                    print("💡   1. Log into Three Mobile in your browser, or")
                    print("💡   2. Configure three_username/three_password in config")
                    return None
        else:
            print("❌ No cookies found in database")
            # No cookies at all - try OAuth fallback
            has_credentials = config.get('three_username') and config.get('three_password')
            if has_credentials:
                print("🔄 No cookies available - attempting OAuth login...")
                oauth_result = _perform_oauth_login(session, config)
                if oauth_result:
                    print("✅ OAuth login successful")
                else:
                    print("❌ API OAuth failed - trying headless browser fallback...")
                    browser_result = _perform_oauth_login_with_render(session, config)
                    if browser_result:
                        print("✅ Browser OAuth login successful")
                    else:
                        print("❌ All authentication methods failed")
                        return None
            else:
                print("⚠️ No cookies and no credentials configured")
                print("💡 Either:")
                print("💡   1. Log into Three Mobile in your browser, or")
                print("💡   2. Configure three_username/three_password in config")
                return None

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
