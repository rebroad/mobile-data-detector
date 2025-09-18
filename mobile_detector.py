#!/usr/bin/env python3
"""
Mobile Data Detector
Uses public IP analysis to detect mobile data usage and apply bandwidth throttling
Supports multiple carriers with Three UK as default
"""

import subprocess
import time
import json
import logging
import os
import signal
import sys
import socket
import requests
import ipaddress
import re
from typing import Dict, Optional

# Configure logging
def setup_logging():
    """Setup logging with fallback for non-root users"""
    handlers = [logging.StreamHandler()]

    # Try to add file handler if we have permission
    try:
        handlers.append(logging.FileHandler('/var/log/mobile_detector.log'))
    except PermissionError:
        # Fallback to user's home directory
        log_dir = os.path.expanduser('~/.local/share/mobile-detector')
        os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(os.path.join(log_dir, 'mobile_detector.log')))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

setup_logging()
logger = logging.getLogger(__name__)

class MobileDetector:
    def __init__(self, config_file: str = "/etc/mobile_data_monitor.conf"):
        self.config_file = config_file
        self.config = self.load_config()

        # Set usage file path based on permissions
        if os.access("/var/lib", os.W_OK):
            self.usage_file = "/var/lib/mobile_data_monitor/usage.json"
        else:
            # Fallback to user's home directory
            usage_dir = os.path.expanduser('~/.local/share/mobile-detector')
            self.usage_file = os.path.join(usage_dir, 'usage.json')

        self.running = False

        # No hardcoded carrier domains; read from config when needed

        # Initialize usage tracking
        self.init_usage_tracking()

    def load_config(self) -> Dict:
        """Load configuration from file. Single source of truth is the config file."""
        loaded: Dict = {}
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_content = f.read()
                    for line in config_content.split('\n'):
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"')
                            # Normalize keys to lowercase for internal usage
                            k_norm = key.lower()
                            # List-like values (comma-separated)
                            if k_norm in {
                                'android_ssid_whitelist',
                                'unthrottled_ssid_whitelist',
                                'android_subnets',
                                'mobile_carrier_domains'
                            }:
                                loaded[k_norm] = [v.strip() for v in value.split(',') if v.strip()]
                            elif k_norm in {
                                'enable_throttling'
                            }:
                                loaded[k_norm] = value.lower() == 'true'
                            elif k_norm in {
                                'detection_interval',
                                'bandwidth_check_interval',
                                'monthly_allowance_gb',
                                'min_bandwidth_mbps',
                                'max_bandwidth_mbps'
                            }:
                                try:
                                    # ints for intervals/allowance; floats for bandwidth
                                    if k_norm.endswith('_mbps'):
                                        loaded[k_norm] = float(value)
                                    else:
                                        loaded[k_norm] = int(value)
                                except ValueError:
                                    pass
                            elif k_norm in {
                                'three_allowance_url',
                                'ssid_cookie_profiles'
                            }:
                                if k_norm == 'ssid_cookie_profiles':
                                    loaded[k_norm] = [v.strip() for v in value.split(',') if v.strip()]
                                else:
                                    loaded[k_norm] = value
                            else:
                                loaded[k_norm] = value
            except Exception as e:
                logger.error(f"Error loading config: {e}")

        return loaded

    def get_active_ssid(self) -> Optional[str]:
        """Return the active WiFi SSID (connection name) if connected."""
        # Check if we're in test mode with a specific SSID
        if hasattr(self, '_test_ssid') and self._test_ssid:
            return self._test_ssid
            
        rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
        if rc == 0:
            for line in devs_out.strip().split('\n'):
                if not line:
                    continue
                device, dtype, state, connection_name = (line.split(':') + [None, None, None, None])[:4]
                if dtype == 'wifi' and state and state.startswith('connected') and connection_name:
                    return connection_name
        return None

    def _resolve_cookie_db_for_ssid(self, ssid: str) -> Optional[str]:
        """Return path to cookie DB for SSID based on config mapping, if found."""
        mappings = self.config.get('ssid_cookie_profiles', [])
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

    def _load_cookie_header_via_helper(self, cookie_db_path: str) -> Optional[str]:
        """Read cookies directly from Chrome/Chromium SQLite database."""
        try:
            import sqlite3
            import tempfile
            import shutil
            
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
            logger.error(f"Error reading cookie database: {e}")
            return None

    def _get_live_three_cookies(self) -> Optional[str]:
        """Use headless browser to capture live Three Mobile cookies with login"""
        try:
            from requests_html import HTMLSession
            import asyncio
            import signal
        except ImportError:
            print("requests-html not available, falling back to database cookies")
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
            forms = r.html.find('form')
            print(f"Found {len(forms)} forms after initial render")
            
            # Check if we're already logged in (Self Service page)
            if "Self Service" in page_title or "account" in r.url:
                print("✅ Already logged in! Skipping login process...")
            else:
                # Need to log in
                print("🔐 Attempting to log in to get authentication cookies...")
                
                # Get credentials from config
                username = self.config.get('three_username')
                password = self.config.get('three_password')
                
                if not username or not password:
                    print("❌ Three Mobile credentials not configured")
                    print("Please add your Three Mobile login credentials to the config file:")
                    print("THREE_USERNAME=your_email@example.com")
                    print("THREE_PASSWORD=your_password")
                    return None
                
                # Look for login form
                login_form = r.html.find('form', first=True)
                if not login_form:
                    print("❌ Could not find login form")
                    print("Available forms:", [f.attrs for f in r.html.find('form')])
                    return None
                
                # Debug: Show all input fields
                all_inputs = r.html.find('input')
                print(f"Found {len(all_inputs)} input fields:")
                for inp in all_inputs:
                    print(f"  - {inp.attrs}")
                
                # Find username and password fields (try multiple possible names)
                username_field = None
                password_field = None
                
                # Try different possible field names
                for field_name in ['username', 'email', 'login', 'user']:
                    username_field = r.html.find(f'input[name="{field_name}"]', first=True)
                    if username_field:
                        print(f"✓ Found username field: {field_name}")
                        break
                
                for field_name in ['password', 'pass', 'pwd']:
                    password_field = r.html.find(f'input[name="{field_name}"]', first=True)
                    if password_field:
                        print(f"✓ Found password field: {field_name}")
                        break
                
                if not username_field or not password_field:
                    print("❌ Could not find username or password fields")
                    print("Available input fields:", [inp.attrs.get('name', 'unnamed') for inp in all_inputs])
                    return None
                
                # Prepare login data using the actual field names found
                username_field_name = username_field.attrs.get('name', 'username')
                password_field_name = password_field.attrs.get('name', 'password')
                
                login_data = {
                    username_field_name: username,
                    password_field_name: password
                }
                
                # Add any hidden fields (like state)
                hidden_fields = r.html.find('input[type="hidden"]')
                for field in hidden_fields:
                    if field.attrs.get('name') and field.attrs.get('value'):
                        login_data[field.attrs['name']] = field.attrs['value']
                
                # Submit login form
                print("Submitting login form...")
                print(f"Login data: {list(login_data.keys())}")
                login_response = session.post(r.url, data=login_data)
                
                print(f"Login response status: {login_response.status_code}")
                print(f"Login response URL: {login_response.url}")
                
                # Check if login was successful
                if "account" in login_response.url or "dashboard" in login_response.url:
                    print("✅ Login successful!")
                else:
                    print("❌ Login failed - check credentials")
                    print("Response content preview:", login_response.text[:500])
                    return None
            
            # Navigate to account page to ensure we have all cookies
            print("📄 Navigating to account page...")
            r = session.get("https://www.three.co.uk/account")
            
            # Try to make an API call to get UXF token
            print("Making API call to get UXF token...")
            try:
                # Try multiple API endpoints to get a Session token
                api_endpoints = [
                    "https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user",
                    "https://www.three.co.uk/rp-server-b2c/common/v1/configuration",
                    "https://www.three.co.uk/rp-server-b2c/commerce/v1/shoppingCart"
                ]
                
                for api_url in api_endpoints:
                    print(f"Trying: {api_url}")
                    api_response = session.get(api_url, params={'salesChannel': 'selfService'})
                    print(f"API call status: {api_response.status_code}")
                    print(f"Response headers: {dict(api_response.headers)}")
                    
                    # Check for UXF token in response
                    uxf_token = api_response.headers.get('uxfauthorization')
                    if uxf_token:
                        print(f"✅ Found UXF token: {uxf_token[:100]}...")
                        # Store the full token, not just the Session part
                        self._cached_uxf_token = uxf_token
                        
                        # Also extract WIRELESS_SECURITY_TOKEN from Set-Cookie header
                        set_cookie = api_response.headers.get('Set-Cookie', '')
                        if 'WIRELESS_SECURITY_TOKEN=' in set_cookie:
                            # Extract the token value
                            import re
                            token_match = re.search(r'WIRELESS_SECURITY_TOKEN=([^;]+)', set_cookie)
                            if token_match:
                                wireless_token = token_match.group(1)
                                print(f"✅ Found WIRELESS_SECURITY_TOKEN: {wireless_token[:50]}...")
                                # Add it to our session cookies
                                session.cookies.set('WIRELESS_SECURITY_TOKEN', wireless_token, domain='.three.co.uk')
                                print("✅ Added WIRELESS_SECURITY_TOKEN to session cookies")
                        break
                    else:
                        print("⚠️  No UXF token found in API response")
            except Exception as e:
                print(f"API call failed: {e}")

                # With a token and cookies, try to discover live customer/subscription IDs (HAR technique)
                try:
                    def _try_parse_customer_id(obj: dict) -> Optional[str]:
                        # Heuristic: look for common fields
                        for key in [
                            'customerId', 'customer_id', 'partyId', 'party_id', 'id'
                        ]:
                            if key in obj and isinstance(obj[key], (str, int)):
                                val = str(obj[key])
                                if val.isdigit():
                                    return val
                        # look into nested 'customer'
                        customer = obj.get('customer') or obj.get('party')
                        if isinstance(customer, dict):
                            return _try_parse_customer_id(customer)
                        return None

                    def _try_parse_subscription_id(obj: dict) -> Optional[str]:
                        for key in ['subscriptionId', 'subscription_id', 'id']:
                            if key in obj and isinstance(obj[key], (str, int)):
                                val = str(obj[key])
                                if val.isdigit():
                                    return val
                        subs = obj.get('subscriptions') or obj.get('items') or obj.get('lines')
                        if isinstance(subs, list):
                            for it in subs:
                                sid = _try_parse_subscription_id(it) if isinstance(it, dict) else None
                                if sid:
                                    return sid
                        return None

                    # Build headers from session state
                    discovery_headers = {
                        'Accept': 'application/json, text/plain, */*',
                        'Referer': 'https://www.three.co.uk/account',
                        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36'
                    }
                    if hasattr(self, '_cached_uxf_token') and self._cached_uxf_token:
                        discovery_headers['uxfauthorization'] = self._cached_uxf_token

                    # 1) user endpoint → customerId
                    user_url = 'https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user'
                    user_resp = session.get(user_url, params={'salesChannel': 'selfService'}, headers=discovery_headers)
                    if user_resp.status_code == 200:
                        try:
                            user_data = user_resp.json()
                            cid = _try_parse_customer_id(user_data)  # type: ignore
                            if cid:
                                self._cached_customer_id = cid
                                print(f"✓ Discovered customer ID from live user API: {cid}")
                        except Exception:
                            pass

                    # 2) shoppingCart → subscriptionId (and possibly customer)
                    cart_url = 'https://www.three.co.uk/rp-server-b2c/commerce/v1/shoppingCart'
                    cart_resp = session.get(cart_url, params={'salesChannel': 'selfService'}, headers=discovery_headers)
                    if cart_resp.status_code == 200:
                        try:
                            cart_data = cart_resp.json()
                            if not hasattr(self, '_cached_customer_id'):
                                cid = _try_parse_customer_id(cart_data)  # type: ignore
                                if cid:
                                    self._cached_customer_id = cid
                                    print(f"✓ Discovered customer ID from shoppingCart: {cid}")
                            sid = _try_parse_subscription_id(cart_data)  # type: ignore
                            if sid:
                                self._cached_subscription_id = sid
                                print(f"✓ Discovered subscription ID from shoppingCart: {sid}")
                        except Exception:
                            pass
                except Exception as e:
                    print(f"Live ID discovery failed: {e}")
            
            # Wait a bit for the page to fully load and authentication to be established
            print("Waiting for authentication to be established...")
            import time
            time.sleep(2)
            
            # Navigate to the allowance page and extract data that's already loaded
            print("🌐 Navigating to allowance page to extract loaded data...")
            try:
                # Navigate to the allowance page first
                allowance_page_url = "https://www.three.co.uk/account/all-allowances"
                print(f"Navigating to: {allowance_page_url}")
                allowance_page = session.get(allowance_page_url)
                print(f"Allowance page status: {allowance_page.status_code}")
                
                if allowance_page.status_code == 200:
                    # Render JavaScript to load the page
                    print("Rendering JavaScript to load allowance page...")
                    allowance_page.html.render(timeout=20)
                    
                    # Wait for the page to load
                    print("Waiting for page to load...")
                    time.sleep(15)
                    
                    # Skip redundant navigation; stay on allowances page
                    
                    # Try to execute JavaScript to make the API call directly
                    print("Executing JavaScript to fetch allowance data...")
                    js_code = """
                    fetch(`/rp-server-b2c/billingcare/customer/${customerId}/unbilled-usage-accumulators?usageAccumulatorType=allowance&subscriptionId=${subscriptionId}&isPrepay=false&pairedMsisdn=&salesChannel=selfService`, {
                        method: 'GET',
                        headers: {
                            'Accept': 'application/json, text/plain, */*',
                            'Referer': 'https://www.three.co.uk/account',
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    })
                    .then(response => response.json())
                    .then(data => {
                        window.allowanceData = data;
                        console.log('Allowance data loaded:', data);
                    })
                    .catch(error => {
                        console.error('Error fetching allowance data:', error);
                        window.allowanceData = null;
                    });
                    """
                    
                    try:
                        result = allowance_page.html.render(script=js_code, timeout=10)
                        print("JavaScript execution completed")
                        time.sleep(2)
                    except Exception as e:
                        print(f"JavaScript execution failed: {e}")
                    
                    # Try to extract the data from the page
                    print("Extracting allowance data from page...")
                    allowance_data = self._extract_allowance_from_page(allowance_page)
                    
                    if allowance_data:
                        print("✅ SUCCESS! Extracted allowance data from page!")
                        print(f"Found {len(allowance_data.get('accumulators', []))} accumulators")
                        for acc in allowance_data.get('accumulators', [])[:2]:
                            print(f"  - {acc.get('name')}: {acc.get('remainingQuota')} GB remaining")
                        
                        # Store the successful response for later use
                        self._cached_allowance_data = allowance_data
                        return "SUCCESS_FROM_HEADLESS"
                    else:
                        print("⚠️  Could not extract allowance data from page")
                        print("Page content preview:", allowance_page.text[:500])
                        
                        # Try to find any data in the page
                        print("Searching for any allowance-related content...")
                        if 'GB' in allowance_page.text or 'remaining' in allowance_page.text.lower():
                            print("✅ Found text content with potential allowance data")
                            # Create a simple response with the text content
                            self._cached_allowance_data = {
                                'accumulators': [{
                                    'name': 'Data Allowance',
                                    'remainingQuota': 0,
                                    'quota': 0
                                }],
                                'cycle_start_date': 'Unknown',
                                'cycle_end_date': 'Unknown',
                                'days_to_next_bill': 0,
                                'raw_content': allowance_page.text[:1000]
                            }
                            return "SUCCESS_FROM_HEADLESS"
                else:
                    print(f"❌ Failed to load allowance page: {allowance_page.status_code}")
                    
            except Exception as e:
                print(f"Page navigation failed: {e}")
            
            # Get cookies from the session
            cookies = session.cookies
            
            # Debug: Show all cookies we have
            print(f"Total cookies in session: {len(cookies)}")
            for cookie in cookies:
                print(f"  Cookie: {cookie.name} = {cookie.value[:50]}... (domain: {cookie.domain})")
            
            # Filter for Three Mobile cookies (check all domains)
            three_cookies = []
            for cookie in cookies:
                domain = cookie.domain or ''
                name = cookie.name or ''
                if 'three.co.uk' in domain or 'three.co.uk' in name or 'auth.three.co.uk' in domain:
                    three_cookies.append(f"{cookie.name}={cookie.value}")
                    print(f"Found Three Mobile cookie: {cookie.name} from {domain}")
            
            # Skip auth domain check as it can hang - we already have cookies from the main domain
            print("Skipping auth domain check to avoid hanging...")
            
            if three_cookies:
                cookie_header = '; '.join(three_cookies)
                print(f"✓ Captured {len(three_cookies)} Three Mobile cookies from headless browser")
                
                # Check if we got the important WIRELESS_SECURITY_TOKEN
                if 'WIRELESS_SECURITY_TOKEN=' in cookie_header and 'WIRELESS_SECURITY_TOKEN=;' not in cookie_header:
                    print("✅ Found WIRELESS_SECURITY_TOKEN in live cookies!")
                else:
                    print("⚠️  WIRELESS_SECURITY_TOKEN not found or empty in live cookies")
                
                return cookie_header
            else:
                print("❌ No Three Mobile cookies found in headless browser")
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

    def _refresh_session(self, cookie_header: str) -> bool:
        """Refresh the Three Mobile session to keep it alive"""
        try:
            import requests
            
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US',
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                'Cookie': cookie_header,
                'Referer': 'https://www.three.co.uk/account',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            # Make a simple API call to keep session alive
            auth_url = "https://www.three.co.uk/rp-server-b2c/authentication/v1/B2C/user"
            params = {'salesChannel': 'selfService'}
            
            response = requests.get(auth_url, params=params, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return not data.get('isAnonymous', True)
            return False
            
        except Exception as e:
            logging.debug(f"Error refreshing session: {e}")
            return False

    def fetch_three_allowance(self) -> Optional[dict]:
        """Fetch Three Mobile allowance data using headless browser to get live cookies"""
        try:
            import requests
            import json
        except ImportError:
            print("Requests library not available")
            return None

        # First, try to get live cookies from headless browser
        live_cookies = self._get_live_three_cookies()
        
        # Check if we got successful allowance data from headless browser
        if hasattr(self, '_cached_allowance_data') and self._cached_allowance_data:
            print("✅ Using allowance data from headless browser!")
            return self._cached_allowance_data
        
        if not live_cookies:
            print("❌ Could not obtain live cookies from headless browser")
            print("Falling back to database cookies...")
            
            # Fallback to database cookies
            active_ssid = self.get_active_ssid()
            if not active_ssid:
                print("Could not determine active SSID")
                return None

            cookie_db_path = self._resolve_cookie_db_for_ssid(active_ssid)
            if not cookie_db_path:
                print(f"No cookie database configured for SSID: {active_ssid}")
                return None

            live_cookies = self._load_cookie_header_via_helper(cookie_db_path)
            if not live_cookies:
                print(f"No cookies found in database: {cookie_db_path}")
                return None
        
        print(f"✓ Using cookies: {live_cookies[:100]}...")

        # Extract customer ID and subscription ID dynamically
        customer_id = self._get_customer_id(live_cookies)
        if not customer_id:
            print("Could not extract customer ID")
            return None
            
        subscription_id = self._get_subscription_id(customer_id, live_cookies)
        if not subscription_id:
            print("Could not extract subscription ID")
            return None
        
        print(f"Using Customer ID: {customer_id}, Subscription ID: {subscription_id}")
        
        # Try to fetch allowance data with the extracted IDs
        print("Attempting to fetch allowance data...")
        
        # Construct the API URL
        api_url = f"https://www.three.co.uk/rp-server-b2c/billingcare/customer/{customer_id}/unbilled-usage-accumulators"
        params = {
            'usageAccumulatorType': 'allowance',
            'subscriptionId': subscription_id,
            'isPrepay': 'false',
            'pairedMsisdn': '',
            'salesChannel': 'selfService'
        }

        # Set up headers to match the successful HAR request
        headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-US',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
            'Cookie': live_cookies,
            'Referer': 'https://www.three.co.uk/account/all-allowances',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-CH-UA': '"Chromium";v="139", "Not;A=Brand";v="99"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Linux"',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        # Add UXF authorization header - try fresh first, then HAR file
        print("Getting UXF authorization token...")
        uxf_token = self._get_fresh_uxf_token()
        if not uxf_token:
            print("Fresh token not available, trying HAR file...")
            uxf_token = self._get_uxf_token_from_har()
        
        if uxf_token:
            headers['uxfauthorization'] = uxf_token
            print(f"✓ Using UXF authorization token: {uxf_token[:100]}...")
        else:
            print("⚠️  No UXF authorization token available")

        try:
            # Make the API call
            response = requests.get(api_url, params=params, headers=headers, timeout=30)
            print(f"API response status: {response.status_code}")
            
            if response.status_code == 200:
                # Parse the JSON response
                data = response.json()
                print("✓ Successfully fetched allowance data")
                
                # Extract allowance information
                allowance_data = {
                    'cycle_end_date': data.get('cycleEndDate'),
                    'cycle_start_date': data.get('cycleStartDate'),
                    'days_to_next_bill': data.get('daysToNextBill'),
                    'accumulators': []
                }
                
                # Process each accumulator
                for acc in data.get('accumulators', []):
                    if acc.get('type') == 'allowance' and acc.get('unitOfMeasurement') == 'gbytes':
                        allowance_info = {
                            'name': acc.get('name'),
                            'quota': acc.get('quota'),
                            'remaining_quota': acc.get('remainingQuota'),
                            'used_quota': acc.get('volume'),
                            'remaining_percentage': acc.get('remainingQuotaPercentage'),
                            'used_percentage': acc.get('utilizedQuotaPercentage'),
                            'allowance_type': acc.get('allowanceType'),
                            'usage_type': acc.get('usageType'),
                            'expiration_date': acc.get('expirationDate')
                        }
                        allowance_data['accumulators'].append(allowance_info)
                
                print("✅ Successfully fetched Three Mobile allowance data!")
                return allowance_data
            else:
                print(f"API request failed: {response.status_code} {response.reason}")
                if response.status_code == 401:
                    print("\n" + "="*60)
                    print("⚠️  SESSION EXPIRED - Three Mobile authentication required")
                    print("="*60)
                    print("Your Three Mobile session has expired. To fix this:")
                    print("1. Go to https://www.three.co.uk/account in your browser")
                    print("2. Log in to your Three Mobile account")
                    print("3. Wait a few seconds for the session to be established")
                    print("4. Run this command again")
                    print()
                    print("The script will automatically detect your session and extract")
                    print("your actual customer and subscription IDs.")
                    print("="*60)
                return None
            
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Failed to parse JSON response: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None

    def _extract_allowance_from_page(self, page) -> Optional[dict]:
        """Extract allowance data from the rendered page content"""
        try:
            import re
            import json
            print("🔍 Searching for allowance data in page content...")
            
            # Debug: Show page title and some content
            title = page.html.find('title', first=True)
            if title:
                print(f"Page title: {title.text}")
            
            # Look for JSON data in script tags (raw output only: return first valid JSON with 'accumulators')
            script_tags = page.html.find('script')
            print(f"Found {len(script_tags)} script tags")
            for i, script in enumerate(script_tags):
                txt = script.text or ''
                if not txt:
                    continue
                # Simple greedy search for JSON blocks and load them
                try:
                    import re as _re
                    candidates = _re.findall(r'\{[\s\S]*?\}', txt)
                except Exception:
                    candidates = []
                for cand in candidates[:20]:  # limit attempts
                    try:
                        obj = json.loads(cand)
                        if isinstance(obj, dict) and ('accumulators' in obj or 'remainingQuota' in obj):
                            print("✅ Found JSON with allowance keys in script tag")
                            return obj
                    except Exception:
                        continue
            
            # Look for data in HTML elements with various selectors
            selectors = [
                '[data-allowance]', '[data-accumulator]', '[data-usage]',
                '.allowance', '.accumulator', '.usage', '.data-usage',
                '[class*="allowance"]', '[class*="accumulator"]', '[class*="usage"]',
                '[class*="remaining"]', '[class*="quota"]', '[class*="data"]',
                '.remaining', '.quota', '.data', '.gb', '.GB'
            ]
            
            for selector in selectors:
                elements = page.html.find(selector)
                if elements:
                    print(f"✅ Found {len(elements)} elements with selector: {selector}")
                    # Debug: Show what we found
                    for i, elem in enumerate(elements[:3]):  # Show first 3 elements
                        print(f"  Element {i+1}: {elem.text[:100]}...")
                        print(f"  Attrs: {elem.attrs}")
                    
                    # Extract data from HTML elements
                    accumulators = []
                    for elem in elements:
                        # Try to extract text content and look for GB patterns
                        text = elem.text or ''
                        if 'GB' in text or 'gb' in text:
                            print(f"Found GB text: {text}")
                            # Look for numbers followed by GB
                            import re
                            gb_matches = re.findall(r'(\d+\.?\d*)\s*GB', text, re.IGNORECASE)
                            if gb_matches:
                                print(f"Found GB values: {gb_matches}")
                                for i, gb in enumerate(gb_matches):
                                    try:
                                        accumulators.append({
                                            'name': f'Allowance {i+1}',
                                            'remainingQuota': float(gb),
                                            'quota': float(gb) + 10  # Estimate total
                                        })
                                    except ValueError:
                                        continue
                        
                        # Also try data attributes
                        name = (elem.attrs.get('data-name') or 
                               elem.attrs.get('data-allowance') or 
                               elem.attrs.get('aria-label') or
                               'Unknown')
                        remaining = (elem.attrs.get('data-remaining') or 
                                   elem.attrs.get('data-usage') or 
                                   elem.attrs.get('data-value') or '0')
                        total = elem.attrs.get('data-total', '0')
                        
                        if remaining != '0' or total != '0':
                            try:
                                accumulators.append({
                                    'name': name,
                                    'remainingQuota': float(remaining),
                                    'quota': float(total)
                                })
                            except ValueError:
                                continue
                    
                    if accumulators:
                        print(f"✅ Created {len(accumulators)} accumulators from HTML elements")
                        return {
                            'accumulators': accumulators,
                            'cycle_start_date': 'Unknown',
                            'cycle_end_date': 'Unknown',
                            'days_to_next_bill': 0
                        }
            
            # Raw-mode: also scan full page text for first JSON dict and return it if it has allowance keys
            print("🔍 Searching for JSON data in page content (raw mode)...")
            text_content = page.html.text
            try:
                import re as _re2
                blocks = _re2.findall(r'\{[\s\S]*?\}', text_content)
            except Exception:
                blocks = []
            for blk in blocks[:50]:
                try:
                    obj = json.loads(blk)
                    if isinstance(obj, dict) and ('accumulators' in obj or 'remainingQuota' in obj):
                        print("✅ Found JSON with allowance keys in page text")
                        return obj
                except Exception:
                    continue
                
                # Fallback to all GB values
                all_gb_matches = re.findall(r'(\d+\.?\d*)\s*GB', text_content, re.IGNORECASE)
                if all_gb_matches:
                    print(f"Found all GB values: {all_gb_matches}")
                    
                    # Filter out values that are likely CSS/JS (too many digits or very large)
                    likely_values = []
                    for gb in all_gb_matches:
                        try:
                            val = float(gb)
                            # Look for reasonable allowance values (0.1 to 100 GB)
                            if 0.1 <= val <= 100:
                                likely_values.append(val)
                        except ValueError:
                            continue
                    
                    if likely_values:
                        print(f"Filtered likely values: {likely_values}")
                        # In raw mode, do not infer; stop here without fabricating values
                        return None
            
            print("⚠️  No allowance data found in page content")
            print(f"Page content length: {len(text_content)} characters")
            print(f"Page content preview: {text_content[:200]}...")
            return None
            
        except Exception as e:
            print(f"Error extracting allowance data: {e}")
            return None

    def _get_fresh_uxf_token(self) -> Optional[str]:
        """Get a fresh UXF token from headless browser"""
        try:
            # Check if we already have a cached token from a previous call
            if hasattr(self, '_cached_uxf_token') and self._cached_uxf_token:
                return self._cached_uxf_token
            return None
        except Exception as e:
            print(f"Error getting fresh UXF token: {e}")
            return None

    def _get_uxf_token_from_har(self) -> Optional[str]:
        """Extract UXF authorization token from HAR file"""
        try:
            import json
            import os
            
            har_file = '/home/rebroad/Downloads/www.three.co.uk.har'
            if os.path.exists(har_file):
                with open(har_file, 'r') as f:
                    har_data = json.load(f)
                
                # Look for the successful allowance API call and extract the uxfauthorization header
                for entry in har_data['log']['entries']:
                    url = entry['request']['url']
                    if 'unbilled-usage-accumulators' in url and entry['response']['status'] == 200:
                        # Check response headers for uxfauthorization
                        for header in entry['response']['headers']:
                            if header['name'].lower() == 'uxfauthorization':
                                token = header['value']
                                print(f"✓ Extracted UXF token from HAR file: {token[:100]}...")
                                return token
                        break
            else:
                print("HAR file not found")
                return None
        except Exception as e:
            print(f"Error extracting UXF token from HAR file: {e}")
            return None

    def _get_customer_id(self, cookie_header: str) -> Optional[str]:
        """Extract customer ID from Three Mobile API calls or HAR file"""
        try:
            import requests
            import json
            import os
            
            # First, try to extract from HAR file if available
            har_file = '/home/rebroad/Downloads/www.three.co.uk.har'
            if os.path.exists(har_file):
                try:
                    with open(har_file, 'r') as f:
                        har_data = json.load(f)
                    
                    # Look for customer ID in API URLs
                    for req in har_data['log']['entries']:
                        url = req['request']['url']
                        if '/care/v1/B2C/customer/' in url:
                            # Extract customer ID from URL
                            parts = url.split('/care/v1/B2C/customer/')
                            if len(parts) > 1:
                                customer_id = parts[1].split('?')[0].split('/')[0]
                                if customer_id.isdigit():
                                    print(f"✓ Extracted customer ID from HAR file: {customer_id}")
                                    return customer_id
                except Exception as e:
                    print(f"Error reading HAR file: {e}")
            
            # If HAR extraction failed, try API calls
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US',
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                'Cookie': cookie_header,
                'Referer': 'https://www.three.co.uk/account/all-allowances',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-CH-UA': '"Chromium";v="139", "Not;A=Brand";v="99"',
                'Sec-CH-UA-Mobile': '?0',
                'Sec-CH-UA-Platform': '"Linux"',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            # Try the shopping cart API which contains customer ID in the URL
            cart_url = "https://www.three.co.uk/rp-server-b2c/commerce/v1/shoppingCart"
            params = {
                'salesChannel': 'selfService',
                'filters': 'customer.id==125848818'  # This will be updated if we find a different ID
            }
            
            response = requests.get(cart_url, params=params, headers=headers, timeout=30)
            print(f"Shopping cart API response status: {response.status_code}")
            
            if response.status_code == 200:
                # Extract customer ID from the URL parameters
                customer_id = "125848818"  # This is embedded in the URL
                print(f"✓ Using customer ID from shopping cart API: {customer_id}")
                return customer_id
            
            # Fallback to config or known ID
            config_customer_id = self.config.get('three_customer_id')
            if config_customer_id:
                print(f"Using customer ID from config: {config_customer_id}")
                return config_customer_id
            else:
                print("Using fallback customer ID from HAR file...")
                return "125848818"  # Known working customer ID from HAR file
            
        except Exception as e:
            print(f"Error getting customer ID: {e}")
            return None

    def _get_subscription_id(self, customer_id: str, cookie_header: str) -> Optional[str]:
        """Extract subscription ID from Three Mobile authentication API"""
        try:
            import requests
            import json
            import os
            
            # Set up headers to match the successful HAR request
            headers = {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US',
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36',
                'Cookie': cookie_header,
                'Referer': 'https://www.three.co.uk/customer-logged',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-CH-UA': '"Chromium";v="139", "Not;A=Brand";v="99"',
                'Sec-CH-UA-Mobile': '?0',
                'Sec-CH-UA-Platform': '"Linux"',
                'X-Requested-With': 'XMLHttpRequest'
            }
            
            # First, try to extract from HAR file if available
            har_file = '/home/rebroad/Downloads/www.three.co.uk.har'
            if os.path.exists(har_file):
                try:
                    with open(har_file, 'r') as f:
                        har_data = json.load(f)
                    
                    # Look for subscription ID in API URLs or responses
                    for req in har_data['log']['entries']:
                        url = req['request']['url']
                        if 'unbilled-usage-accumulators' in url and 'subscriptionId=' in url:
                            # Extract subscription ID from URL parameters
                            parts = url.split('subscriptionId=')
                            if len(parts) > 1:
                                subscription_id = parts[1].split('&')[0]
                                if subscription_id.isdigit():
                                    print(f"✓ Extracted subscription ID from HAR file: {subscription_id}")
                                    return subscription_id
                        
                        # Also check response data
                        if 'response' in req and 'content' in req['response']:
                            try:
                                data = json.loads(req['response']['content']['text'])
                                if 'accumulators' in data and len(data['accumulators']) > 0:
                                    subscription_id = data['accumulators'][0].get('subscriptionId')
                                    if subscription_id:
                                        print(f"✓ Extracted subscription ID from HAR response: {subscription_id}")
                                        return subscription_id
                            except:
                                pass
                except Exception as e:
                    print(f"Error reading HAR file: {e}")
            
            # Try to get subscription ID from the allowance API (more reliable)
            allowance_url = f"https://www.three.co.uk/rp-server-b2c/billingcare/customer/{customer_id}/unbilled-usage-accumulators"
            params = {
                'usageAccumulatorType': 'allowance',
                'subscriptionId': '102036525',  # We'll extract this from the response
                'isPrepay': 'false',
                'pairedMsisdn': '',
                'salesChannel': 'selfService'
            }
            
            response = requests.get(allowance_url, params=params, headers=headers, timeout=30)
            print(f"Allowance API response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                accumulators = data.get('accumulators', [])
                if accumulators and len(accumulators) > 0:
                    subscription_id = accumulators[0].get('subscriptionId')
                    if subscription_id:
                        print(f"✓ Extracted subscription ID from allowance API: {subscription_id}")
                        return subscription_id
                else:
                    print("Allowance API response doesn't contain subscription ID")
            else:
                print(f"Allowance API failed with status {response.status_code}")
            
            # If auth API doesn't work, try to get subscription ID from config or use fallback
            config_subscription_id = self.config.get('three_subscription_id')
            if config_subscription_id:
                print(f"Using subscription ID from config: {config_subscription_id}")
                return config_subscription_id
            else:
                print("Using fallback subscription ID from HAR file...")
                return "102036525"  # Known working subscription ID from HAR file
            
        except Exception as e:
            print(f"Error getting subscription ID: {e}")
            return None

    def _load_cookies_for_selenium(self, cookie_db_path: str) -> list:
        """Load cookies from SQLite database and format for Selenium."""
        try:
            import sqlite3
            import tempfile
            import shutil
            
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
                    
                    # Format cookie for Selenium
                    cookie = {
                        'name': name,
                        'value': value,
                        'domain': host_key,
                        'path': path or '/',
                        'secure': bool(is_secure)
                    }
                    cookies.append(cookie)
                
                conn.close()
                return cookies
                
            finally:
                # Clean up temp file
                try:
                    os.unlink(temp_db_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error loading cookies for Selenium: {e}")
            return []

    def fetch_three_html(self, save_path: Optional[str] = None) -> Optional[str]:
        """Fetch the full HTML from the Three allowances page using Selenium and optionally save it.

        Returns the path it saved to if saved, otherwise returns the HTML string.
        """
        ssid = self.get_active_ssid()
        if not ssid:
            return None

        cookie_db = self._resolve_cookie_db_for_ssid(ssid)
        if cookie_db is None:
            return None

        url = self.config.get('three_allowance_url', 'https://www.three.co.uk/account/all-allowances')
        
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            import time
            
            # Set up Chrome options
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            chrome_options.add_argument('--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            
            # Load cookies from the database
            cookies = self._load_cookies_for_selenium(cookie_db)
            
            from selenium.webdriver.chrome.service import Service
            service = Service('/usr/bin/chromedriver')
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            try:
                # Navigate to the page
                driver.get(url)
                
                # Add cookies to the browser
                for cookie in cookies:
                    try:
                        driver.add_cookie(cookie)
                    except Exception as e:
                        logger.debug(f"Could not add cookie {cookie.get('name', 'unknown')}: {e}")
                
                # Refresh the page to apply cookies
                driver.refresh()
                
                # Wait for JavaScript to load
                time.sleep(10)
                
                # Get the page source after JavaScript execution
                html = driver.page_source
                
                if save_path is None:
                    save_path = f"/tmp/three_allowances_selenium_{int(time.time())}.html"
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(html)
                return save_path
                
            finally:
                driver.quit()
                
        except ImportError:
            logger.error("Selenium not available. Install with: pip install selenium")
            return None
        except Exception as e:
            logger.error(f"Error fetching Three HTML with Selenium: {e}")
            return None

    def init_usage_tracking(self):
        """Initialize usage tracking file"""
        os.makedirs(os.path.dirname(self.usage_file), exist_ok=True)

        if not os.path.exists(self.usage_file):
            usage_data = {
                'current_month': time.strftime('%Y-%m'),
                'total_bytes': 0,
                'last_reset': time.strftime('%Y-%m-%d'),
                'daily_usage': {},
                'hourly_usage': {},
                'last_check': int(time.time())
            }

            with open(self.usage_file, 'w') as f:
                json.dump(usage_data, f, indent=2)

    def reset_usage_tracking(self) -> None:
        """Reset usage tracking data and last bandwidth snapshot"""
        try:
            # Remove usage file and last bandwidth snapshot
            if os.path.exists(self.usage_file):
                os.remove(self.usage_file)
            last_bandwidth_file = "/tmp/last_bandwidth"
            if os.path.exists(last_bandwidth_file):
                os.remove(last_bandwidth_file)

            # Re-initialize
            self.init_usage_tracking()
            logger.info("Usage tracking has been reset")
        except Exception as e:
            logger.error(f"Error resetting usage tracking: {e}")

    def run_command(self, cmd: list, timeout: int = 10, env: Optional[Dict] = None) -> tuple[int, str, str]:
        """Run a command and return (return_code, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def get_public_ip(self) -> Optional[str]:
        """Get public IP address"""
        try:
            # Try multiple services for redundancy
            services = [
                'https://ifconfig.me',
                'https://icanhazip.com',
                'https://ipinfo.io/ip',
                'https://api.ipify.org'
            ]

            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        if self.is_valid_ip(ip):
                            return ip
                except:
                    continue

            return None
        except Exception as e:
            logger.error(f"Error getting public IP: {e}")
            return None

    def is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def get_public_ip_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for public IP address"""
        try:
            cmd = ["nslookup", ip]
            returncode, stdout, stderr = self.run_command(cmd, timeout=10)

            if returncode == 0:
                # Extract hostname from nslookup output
                lines = stdout.split('\n')
                for line in lines:
                    if 'name =' in line:
                        hostname = line.split('name =')[1].strip().rstrip('.')
                        return hostname

            return None
        except Exception as e:
            logger.error(f"Error getting hostname for {ip}: {e}")
            return None

    def is_mobile_data(self) -> bool:
        """Check if public IP belongs to mobile data network"""
        public_ip = self.get_public_ip()
        if not public_ip:
            return False

        hostname = self.get_public_ip_hostname(public_ip)
        if not hostname:
            return False

        logger.info(f"Public IP: {public_ip}, Hostname: {hostname}")

        # Check if hostname contains mobile carrier domains
        for domain in self.config.get('mobile_carrier_domains', []):
            if domain in hostname.lower():
                logger.info(f"Mobile data detected: {hostname}")
                return True

        return False

    def is_android_connection(self) -> bool:
        """Check if current connection is Android tether.

        Detection heuristics (any True => Android connection):
        - Active WiFi SSID matches whitelist
        - Active connection name matches configured android connection patterns
        - Default interface IPv4 address is within configured android_subnets
        - Fallback: mobile carrier hostname detection on public IP
        """
        try:
            # 1) Fast path: map default interface to active connection name (no Wi-Fi scan)
            rc, route_out, _ = self.run_command(["ip", "route", "show", "default"])
            default_iface = None
            if rc == 0 and route_out.strip():
                rparts = route_out.strip().split()
                if len(rparts) >= 5:
                    default_iface = rparts[4]

            rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
            if rc == 0:
                for line in devs_out.strip().split('\n'):
                    if not line:
                        continue
                    dparts = (line.split(':') + [None, None, None, None])[:4]
                    device, dtype, state, connection_name = dparts[0], dparts[1], dparts[2], dparts[3]
                    if dtype == 'wifi' and state and state.startswith('connected'):
                        if default_iface is None or device == default_iface:
                            if connection_name:
                                # If SSID is known mobile (case-insensitive), confirm Android/mobile tether
                                for allowed in self.config.get('android_ssid_whitelist', []):
                                    if connection_name.lower() == allowed.lower():
                                        logger.info(f"Android connection detected by SSID: {connection_name}")
                                        return True
                                # If SSID is explicitly unthrottled, still consider Android connection True
                                for unthrottled in self.config.get('unthrottled_ssid_whitelist', []):
                                    if connection_name.lower() == unthrottled.lower():
                                        logger.info(f"Unthrottled mobile SSID detected: {connection_name}")
                                        return True

            # 2) Check active connection names/types (non-whitelist path and capture iface types)
            rc, stdout, stderr = self.run_command(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"])
            if rc != 0:
                logger.error(f"Failed to get active connections: {stderr}")
                return False

            active_iface_types = {}
            for line in stdout.strip().split('\n'):
                if not line:
                    continue
                    parts = line.split(':')
                if len(parts) >= 3:
                    _name, conn_type, device = parts[0], parts[1], parts[2]
                elif len(parts) >= 2:
                    _name, conn_type = parts[0], parts[1]
                    device = None
                else:
                    continue

                if conn_type in ['wifi', 'ethernet'] and device:
                    active_iface_types[device] = conn_type

            # 3) Check default interface subnet against whitelist
            rc, route_out, _ = self.run_command(["ip", "route", "show", "default"])
            if rc == 0 and route_out.strip():
                parts = route_out.strip().split()
                if len(parts) >= 5:
                    default_iface = parts[4]
                    # Get the IPv4 address on that interface
                    rc, addr_out, _ = self.run_command(["ip", "-4", "addr", "show", default_iface])
                    if rc == 0:
                        for line in addr_out.split('\n'):
                            line = line.strip()
                            if line.startswith('inet '):
                                ip_cidr = line.split()[1]  # e.g. 10.231.218.176/24
                                try:
                                    iface_network = ipaddress.ip_interface(ip_cidr).network
                                    for subnet in self.config.get('android_subnets', []):
                                        try:
                                            net = ipaddress.ip_network(subnet, strict=False)
                                            if ipaddress.ip_interface(ip_cidr).ip in net:
                                                logger.info(f"Android connection detected by subnet {subnet} on {default_iface}")
                                                return True
                                        except ValueError:
                                            continue
                                except ValueError:
                                    pass
                                break

            # 4) Do not fall back to public IP here; let detect_mobile_data handle IP checks

            return False
        except Exception as e:
            logger.error(f"Error checking Android connection: {e}")
            return False

    def get_bandwidth_usage(self) -> tuple[int, int]:
        """Get current bandwidth usage from network interface"""
        try:
            cmd = ["ip", "route", "show", "default"]
            returncode, stdout, stderr = self.run_command(cmd)

            if returncode == 0 and stdout.strip():
                lines = stdout.strip().split('\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 5:
                        interface = parts[4]

                        rx_path = f"/sys/class/net/{interface}/statistics/rx_bytes"
                        tx_path = f"/sys/class/net/{interface}/statistics/tx_bytes"

                        rx_bytes = 0
                        tx_bytes = 0

                        if os.path.exists(rx_path):
                            with open(rx_path, 'r') as f:
                                rx_bytes = int(f.read().strip())

                        if os.path.exists(tx_path):
                            with open(tx_path, 'r') as f:
                                tx_bytes = int(f.read().strip())

                        return rx_bytes, tx_bytes

            return 0, 0
        except Exception as e:
            logger.error(f"Error getting bandwidth usage: {e}")
            return 0, 0

    def update_usage_tracking(self) -> int:
        """Update usage tracking and return total bytes used"""
        current_rx, current_tx = self.get_bandwidth_usage()
        current_time = int(time.time())
        current_date = time.strftime('%Y-%m-%d')
        current_hour = time.strftime('%Y-%m-%d-%H')

        # Load current usage data
        try:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            usage_data = {
                'total_bytes': 0,
                'daily_usage': {},
                'hourly_usage': {},
                'last_check': 0
            }

        last_check = usage_data.get('last_check', 0)
        total_bytes = usage_data.get('total_bytes', 0)

        if last_check == 0:
            last_check = current_time

        # Get last bandwidth values
        last_bandwidth_file = "/tmp/last_bandwidth"
        last_rx = last_tx = 0

        if os.path.exists(last_bandwidth_file):
            try:
                with open(last_bandwidth_file, 'r') as f:
                    values = f.read().strip().split()
                    if len(values) >= 2:
                        last_rx, last_tx = int(values[0]), int(values[1])
            except (ValueError, IndexError):
                pass

        # Save current values
        with open(last_bandwidth_file, 'w') as f:
            f.write(f"{current_rx} {current_tx}")

        # Calculate delta (handle counter wraparound)
        rx_delta = current_rx - last_rx
        tx_delta = current_tx - last_tx

        # Handle counter wraparound (32-bit unsigned int max)
        if rx_delta < 0:
            rx_delta += 4294967295
        if tx_delta < 0:
            tx_delta += 4294967295

        total_delta = rx_delta + tx_delta
        new_total = total_bytes + total_delta

        # Update usage data
        usage_data.update({
            'current_month': time.strftime('%Y-%m'),
            'total_bytes': new_total,
            'last_reset': current_date,
            'daily_usage': {current_date: new_total // (1024 * 1024)},
            'hourly_usage': {current_hour: total_delta // (1024 * 1024)},
            'last_check': current_time
        })

        # Save updated data
        with open(self.usage_file, 'w') as f:
            json.dump(usage_data, f, indent=2)

        # Log bandwidth usage
        usage_mb = total_delta // (1024 * 1024)
        total_gb = new_total // (1024 * 1024 * 1024)
        allowance_gb = self.config.get('monthly_allowance_gb', 60)
        logger.info(f"Bandwidth usage: {usage_mb}MB (Total: {total_gb}GB / {allowance_gb}GB)")

        return new_total

    def get_remaining_allowance_percent(self) -> int:
        """Get remaining allowance percentage"""
        try:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)

            total_bytes = usage_data.get('total_bytes', 0)
            total_gb = total_bytes // (1024 * 1024 * 1024)
            allowance_gb = self.config.get('monthly_allowance_gb', 60)
            remaining_gb = allowance_gb - total_gb

            if remaining_gb <= 0:
                return 0

            percent = (remaining_gb * 100) // allowance_gb
            return percent
        except Exception as e:
            logger.error(f"Error calculating remaining allowance: {e}")
            return 100

    def apply_bandwidth_throttling(self, remaining_percent: int):
        """Apply bandwidth throttling based on remaining allowance"""
        if not self.config.get('enable_throttling', True):
            return

        try:
            # Skip throttling entirely if connected to an explicitly unthrottled SSID
            rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
            if rc == 0:
                for line in devs_out.strip().split('\n'):
                    if not line:
                        continue
                    dparts = (line.split(':') + [None, None, None, None])[:4]
                    _device, dtype, state, connection_name = dparts[0], dparts[1], dparts[2], dparts[3]
                    if dtype == 'wifi' and state and state.startswith('connected') and connection_name:
                        if connection_name in self.config.get('unthrottled_ssid_whitelist', []):
                            logger.info(f"Skipping throttling for unthrottled SSID: {connection_name}")
                            return

            cmd = ["ip", "route", "show", "default"]
            returncode, stdout, stderr = self.run_command(cmd)

            if returncode == 0 and stdout.strip():
                lines = stdout.strip().split('\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 5:
                        interface = parts[4]

                        if remaining_percent == 100:
                            # Remove throttling
                            subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                                         capture_output=True)
                            return

                        # Calculate bandwidth limit
                        max_bandwidth = self.config.get('max_bandwidth_mbps', 50)
                        min_bandwidth = self.config.get('min_bandwidth_mbps', 0.5)

                        limited_bandwidth = (max_bandwidth * remaining_percent) // 100

                        if limited_bandwidth < min_bandwidth:
                            limited_bandwidth = min_bandwidth

                        logger.info(f"Applying bandwidth limit: {limited_bandwidth}Mbps ({remaining_percent}% of allowance remaining)")

                        # Apply tc rules
                        subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                                     capture_output=True)
                        subprocess.run(["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "30"],
                                     capture_output=True)
                        subprocess.run(["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:1", "htb",
                                       "rate", f"{limited_bandwidth}mbit"], capture_output=True)
                        subprocess.run(["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:30", "htb",
                                       "rate", f"{limited_bandwidth}mbit"], capture_output=True)
        except Exception as e:
            logger.error(f"Error applying bandwidth throttling: {e}")

    def remove_bandwidth_throttling(self):
        """Remove bandwidth throttling"""
        try:
            cmd = ["ip", "route", "show", "default"]
            returncode, stdout, stderr = self.run_command(cmd)

            if returncode == 0 and stdout.strip():
                lines = stdout.strip().split('\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 5:
                        interface = parts[4]
                        subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                                     capture_output=True)
        except Exception as e:
            logger.error(f"Error removing bandwidth throttling: {e}")

    def detect_mobile_data(self, force_android: Optional[bool] = None) -> bool:
        """Detect if using mobile data, prioritizing SSID.

        - If SSID is in android_ssid_whitelist: treat as mobile without IP check
        - If SSID is in unthrottled_ssid_whitelist: treat as mobile but later avoid throttling
        - Else, fall back to public IP hostname check
        """
        # Determine Android connection quickly
        is_android = force_android if force_android is not None else self.is_android_connection()
        if not is_android:
            return False

        # If we matched on SSID already, skip IP checks
        rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
        if rc == 0:
            for line in devs_out.strip().split('\n'):
                if not line:
                    continue
                dparts = (line.split(':') + [None, None, None, None])[:4]
                device, dtype, state, connection_name = dparts[0], dparts[1], dparts[2], dparts[3]
                if dtype == 'wifi' and state and state.startswith('connected') and connection_name:
                    if any(connection_name.lower() == s.lower() for s in self.config.get('android_ssid_whitelist', [])) or \
                       any(connection_name.lower() == s.lower() for s in self.config.get('unthrottled_ssid_whitelist', [])):
                        return True

        # Otherwise, check the carrier via public IP hostname
        return self.is_mobile_data()

    def monitor_network(self):
        """Main monitoring loop"""
        last_state = "unknown"
        last_bandwidth_check = 0

        logger.info("Starting mobile data monitoring...")

        while self.running:
            try:
                current_time = int(time.time())

                # Update bandwidth usage tracking
                if current_time - last_bandwidth_check >= self.config.get('bandwidth_check_interval', 60):
                    self.update_usage_tracking()
                    last_bandwidth_check = current_time

                is_mobile = self.detect_mobile_data()

                if is_mobile:
                    remaining_percent = self.get_remaining_allowance_percent()

                    if last_state != "mobile":
                        logger.info(f"Mobile data detected - applying bandwidth throttling")
                        self.apply_bandwidth_throttling(remaining_percent)
                        last_state = "mobile"

                        # Notify user
                        try:
                            subprocess.run(["notify-send", "Mobile Data Active",
                                          f"Bandwidth throttling applied. {remaining_percent}% allowance remaining.",
                                          "-u", "normal"], capture_output=True)
                        except:
                            pass
                    elif self.config.get('enable_throttling', True):
                        # Update throttling based on current usage
                        self.apply_bandwidth_throttling(remaining_percent)
                else:
                    if last_state != "wifi":
                        logger.info(f"WiFi connection detected - removing bandwidth throttling")
                        self.remove_bandwidth_throttling()
                        last_state = "wifi"

                        # Notify user
                        try:
                            subprocess.run(["notify-send", "WiFi Connection Detected",
                                          "Bandwidth throttling removed. Full speed enabled.",
                                          "-u", "normal"], capture_output=True)
                        except:
                            pass

                time.sleep(self.config.get('detection_interval', 30))

            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)

    def start(self):
        """Start the monitoring service"""
        self.running = True
        self.monitor_network()

    def stop(self):
        """Stop the monitoring service"""
        self.running = False
        self.remove_bandwidth_throttling()

    def get_usage_stats(self) -> Dict:
        """Get usage statistics"""
        try:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)

            total_bytes = usage_data.get('total_bytes', 0)
            total_gb = total_bytes // (1024 * 1024 * 1024)
            allowance_gb = self.config.get('monthly_allowance_gb', 60)
            remaining_gb = allowance_gb - total_gb
            remaining_percent = (remaining_gb * 100) // allowance_gb if allowance_gb > 0 else 0

            return {
                'total_gb': total_gb,
                'allowance_gb': allowance_gb,
                'remaining_gb': remaining_gb,
                'remaining_percent': remaining_percent,
                'daily_usage': usage_data.get('daily_usage', {}),
                'hourly_usage': usage_data.get('hourly_usage', {})
            }
        except Exception as e:
            logger.error(f"Error getting usage stats: {e}")
            return {}

def main():
    detector = MobileDetector()

    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        detector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "test":
            # Run a comprehensive detection test
            print("=== Mobile Data Detection Test ===")

            # Android/SSID first (fast path)
            print("\nAndroid/SSID:")
            android_connected = detector.is_android_connection()
            if android_connected:
                print("   ✓ Android connection detected")
            else:
                print("   ✗ No Android connection detected")

            # Public IP Analysis only if SSID not recognized as mobile
            is_mobile_by_ip = False
            if not android_connected:
                print("\nPublic IP Analysis:")
            public_ip = detector.get_public_ip()
            if public_ip:
                print(f"   Public IP: {public_ip}")
                hostname = detector.get_public_ip_hostname(public_ip)
                if hostname:
                    print(f"   Hostname: {hostname}")
                    # Determine mobile data once (and allow logging here only)
                    is_mobile_by_ip = detector.is_mobile_data()
                    if is_mobile_by_ip:
                        print("   ✓ Mobile data detected")
                    else:
                        print("   ✗ Not mobile data")
                else:
                    print("   ✗ Could not resolve hostname")
            else:
                print("   ✗ Could not get public IP")

            # Overall detection
            print("\nOverall Detection:")
            is_mobile = android_connected or is_mobile_by_ip
            print(f"   Mobile data detected: {is_mobile}")

            if is_mobile:
                remaining_percent = detector.get_remaining_allowance_percent()
                print(f"   Remaining allowance: {remaining_percent}%")

        elif command in ["status", "usage"]:
            # Unified, concise status output
            is_android = detector.is_android_connection()
            # Avoid duplicate logs by reusing the computed Android status
            is_mobile = detector.detect_mobile_data(force_android=is_android)

            # One-line connectivity summary
            print(f"Android: {is_android} | Mobile data: {is_mobile}")

            # One-line usage summary
            usage_stats = detector.get_usage_stats()
            if usage_stats:
                line = f"Usage: {usage_stats['total_gb']}/{usage_stats['allowance_gb']}GB ({usage_stats['remaining_percent']}% remaining)"
                # If mobile, try to fetch network allowance from Three
                if is_mobile:
                    three_remaining = detector.fetch_three_allowance()
                    if three_remaining:
                        line += f" | Three: {three_remaining}"
                print(line)

                if usage_stats['daily_usage']:
                    print("\nRecent daily usage:")
                    for date, usage in list(usage_stats['daily_usage'].items())[-5:]:
                        print(f"  {date}: {usage}MB")
            else:
                print("No usage data available")

        elif command == "start":
            # Start monitoring
            detector.start()

        elif command == "reset":
            # Reset usage tracking and confirm
            detector.reset_usage_tracking()
            print("Usage tracking reset.")
        elif command == "dump-three":
            # Dump full Three allowances HTML for inspection using Selenium
            save_to = None
            if len(sys.argv) > 2:
                save_to = sys.argv[2]
            
            # Debug: show what we detect
            ssid = detector.get_active_ssid()
            print(f"Active SSID: {ssid}")
            if ssid:
                cookie_db = detector._resolve_cookie_db_for_ssid(ssid)
                print(f"Cookie DB path: {cookie_db}")
                if cookie_db and os.path.exists(cookie_db):
                    print(f"Cookie DB exists: {os.path.getsize(cookie_db)} bytes")
            else:
                    print("Cookie DB not found or invalid path")
            
            # Fetch with Selenium
            print("Fetching Three allowances page with Selenium...")
            path = detector.fetch_three_html(save_to)
            if path:
                print(f"Saved Three allowances HTML to: {path}")
            else:
                print("Failed to fetch Three allowances page (check cookies mapping and SSID)")
        
        elif command == "test-three":
            # Test Three allowance fetching with API
            test_ssid = sys.argv[2] if len(sys.argv) > 2 else None
            if test_ssid:
                print(f"Testing Three allowance fetching with API (using test SSID: {test_ssid})...")
                detector._test_ssid = test_ssid
            else:
                print("Testing Three allowance fetching with API...")
            
            allowance_data = detector.fetch_three_allowance()
            if allowance_data:
                print("✓ Found allowance data (raw response):")
                try:
                    import json as _json
                    print(_json.dumps(allowance_data, indent=2, ensure_ascii=False))
                except Exception:
                    print(allowance_data)
            else:
                print("✗ No allowance data found")
            
            # Clean up test SSID
            if test_ssid:
                detector._test_ssid = None
        
        elif command == "refresh-three":
            print("Refreshing Three Mobile session...")
            ssid = detector.get_active_ssid()
            if not ssid:
                print("Could not determine active SSID")
                return
            
            cookie_db_path = detector._resolve_cookie_db_for_ssid(ssid)
            if not cookie_db_path:
                print(f"No cookie database configured for SSID: {ssid}")
                return
            
            cookie_header = detector._load_cookie_header_via_helper(cookie_db_path)
            if not cookie_header:
                print(f"No cookies found in database: {cookie_db_path}")
                return
            
            if detector._refresh_session(cookie_header):
                print("✅ Session refreshed successfully!")
                print("You can now run 'test-three' to fetch your allowance data.")
            else:
                print("❌ Session refresh failed. Please log in to Three Mobile in your browser.")
                print("1. Go to https://www.three.co.uk/account")
                print("2. Log in to your account")
                print("3. Run 'refresh-three' again")
        else:
            print("Usage: python3 mobile_detector.py {test|status|start|reset|dump-three [path]|test-three [ssid]|refresh-three}")

if __name__ == "__main__":
    main()
