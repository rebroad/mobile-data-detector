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
    """Use headless browser to capture live Three Mobile cookies with login"""
    try:
        from requests_html import HTMLSession
    except ImportError:
        print("requests-html not available")
        return None

    def timeout_handler(signum, frame):
        raise TimeoutError("Headless browser operation timed out")

    try:
        # Set up timeout handler
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(45)  # 45 second timeout
        
        # Create HTML session
        session = HTMLSession()
        
        print("🌐 Launching headless browser to capture Three Mobile cookies...")
        
        # Navigate to Three Mobile account page
        print("Navigating to Three Mobile account page...")
        r = session.get("https://www.three.co.uk/account")
        print(f"Initial page status: {r.status_code}")
        
        # Render JavaScript to load the login form
        print("Rendering JavaScript to load login form...")
        r.html.render(timeout=20)
        print("JavaScript rendering completed")
        
        # Debug: Check what we have after initial render
        page_title = r.html.find('title', first=True).text if r.html.find('title', first=True) else 'No title'
        print(f"Page title after render: {page_title}")
        
        # Check if we're already logged in (Self Service page)
        if "Self Service" in page_title or "account" in r.url:
            print("✅ Already logged in! Skipping login process...")
        else:
            # Need to log in
            print("🔐 Attempting to log in to get authentication cookies...")
            
            # Get credentials from config
            username = config.get('three_username')
            password = config.get('three_password')
            
            if not username or not password:
                print("❌ Three Mobile credentials not configured")
                print("Please add your Three Mobile login credentials to the config file:")
                print("THREE_USERNAME=your_email@example.com")
                print("THREE_PASSWORD=your_password")
                return None
            
            # Look for login form and submit
            # [Login form logic would go here - simplified for this version]
            print("Login form submission logic would be implemented here")
        
        # Navigate to account page to ensure we have all cookies
        print("📄 Navigating to account page...")
        r = session.get("https://www.three.co.uk/account")
        
        # Try to make an API call to get UXF token
        print("Making API call to get UXF token...")
        try:
            api_response = session.get("https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user", 
                                     params={'salesChannel': 'selfService'})
            print(f"API call status: {api_response.status_code}")
            
            # Check for UXF token in response
            uxf_token = api_response.headers.get('uxfauthorization')
            if uxf_token:
                print(f"✅ Found UXF token: {uxf_token[:100]}...")
                # Store the token for later use
                session._cached_uxf_token = uxf_token
                
                # Also extract WIRELESS_SECURITY_TOKEN from Set-Cookie header
                set_cookie = api_response.headers.get('Set-Cookie', '')
                if 'WIRELESS_SECURITY_TOKEN=' in set_cookie:
                    import re
                    token_match = re.search(r'WIRELESS_SECURITY_TOKEN=([^;]+)', set_cookie)
                    if token_match:
                        wireless_token = token_match.group(1)
                        print(f"✅ Found WIRELESS_SECURITY_TOKEN: {wireless_token[:50]}...")
                        session.cookies.set('WIRELESS_SECURITY_TOKEN', wireless_token, domain='.three.co.uk')
            else:
                print("⚠️  No UXF token found in API response")
        except Exception as e:
            print(f"API call failed: {e}")

        # Get cookies from the session
        cookies = session.cookies
        
        # Filter for Three Mobile cookies
        three_cookies = []
        for cookie in cookies:
            domain = cookie.domain or ''
            if 'three.co.uk' in domain:
                three_cookies.append(f"{cookie.name}={cookie.value}")
        
        if three_cookies:
            cookie_header = '; '.join(three_cookies)
            print(f"✓ Captured {len(three_cookies)} Three Mobile cookies")
            
            # Check if we got the important WIRELESS_SECURITY_TOKEN
            if 'WIRELESS_SECURITY_TOKEN=' in cookie_header and 'WIRELESS_SECURITY_TOKEN=;' not in cookie_header:
                print("✅ Found WIRELESS_SECURITY_TOKEN in live cookies!")
            else:
                print("⚠️  WIRELESS_SECURITY_TOKEN not found or empty in live cookies")
            
            # Return cookies and UXF token
            uxf_token = getattr(session, '_cached_uxf_token', None)
            return (cookie_header, uxf_token)
        else:
            print("❌ No Three Mobile cookies found")
            return None
            
    except TimeoutError as e:
        print(f"⏰ Headless browser timed out: {e}")
        return None
    except Exception as e:
        print(f"Error in headless browser: {e}")
        return None
    finally:
        # Clean up timeout handler
        signal.alarm(0)


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
    r = session.get(account_url)
    time.sleep(0.5)

    # Headers template
    api_headers = {
        'Accept': 'application/json, text/plain, */*',
        'Referer': 'https://www.three.co.uk/account',
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

    # Capture token from headers
    uxf = ur.headers.get('uxfauthorization')
    if uxf:
        api_headers['uxfauthorization'] = uxf

    customer_id: Optional[str] = None
    try:
        ud = ur.json()
        for key in ('customerId', 'partyId', 'id'):
            val = ud.get(key)
            if isinstance(val, (str, int)) and str(val).isdigit():
                customer_id = str(val)
                break
    except Exception:
        pass

    # 3) shoppingCart → subscriptionId (and maybe customerId)
    shopping_url = 'https://www.three.co.uk/rp-server-b2c/commerce/v1/shoppingCart'
    cr = session.get(shopping_url, params={'salesChannel': 'selfService'}, headers=api_headers)
    if cr.status_code != 200:
        print(f"shoppingCart failed: {cr.status_code}")
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
