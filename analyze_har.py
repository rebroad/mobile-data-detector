#!/usr/bin/env python3
"""
HAR File Analysis Tool
Extracts navigation flow and key requests from Three Mobile HAR files for comparison with script behavior.
"""

import json
import sys
import urllib.parse
from typing import List, Dict, Any
from datetime import datetime

def parse_har_file(har_path: str) -> Dict[str, Any]:
    """Parse HAR file and return structured data"""
    try:
        with open(har_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading HAR file: {e}")
        return {}

def extract_navigation_flow(har_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract navigation flow from HAR entries"""
    entries = har_data.get('log', {}).get('entries', [])
    
    navigation_steps = []
    
    for entry in entries:
        request = entry.get('request', {})
        response = entry.get('response', {})
        timings = entry.get('timings', {})
        
        url = request.get('url', '')
        method = request.get('method', '')
        status = response.get('status', 0)
        
        # Parse URL components
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or '/'
        
        # Determine request type
        request_type = 'unknown'
        if 'auth.three.co.uk' in hostname:
            request_type = 'auth0'
        elif 'www.three.co.uk' in hostname:
            request_type = 'three_www'
        elif 'three.co.uk' in hostname:
            request_type = 'three_domain'
        elif 'api' in hostname or '/api/' in path:
            request_type = 'api'
        elif 'login' in path.lower():
            request_type = 'login'
        elif 'account' in path.lower():
            request_type = 'account'
        elif 'allowance' in path.lower():
            request_type = 'allowance'
        
        # Extract key headers
        headers = {h['name'].lower(): h['value'] for h in request.get('headers', [])}
        
        # Extract cookies
        cookies = {}
        cookie_header = headers.get('cookie', '')
        if cookie_header:
            for cookie in cookie_header.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    cookies[name] = value
        
        # Extract response content type
        response_headers = {h['name'].lower(): h['value'] for h in response.get('headers', [])}
        content_type = response_headers.get('content-type', '')
        
        # Check for redirects
        is_redirect = status in [301, 302, 303, 307, 308]
        location = response_headers.get('location', '') if is_redirect else ''
        
        # Check for JavaScript/AJAX
        is_ajax = headers.get('x-requested-with') == 'XMLHttpRequest'
        
        # Check for form submission
        is_form = method == 'POST' and 'application/x-www-form-urlencoded' in headers.get('content-type', '')
        
        step = {
            'url': url,
            'hostname': hostname,
            'path': path,
            'method': method,
            'status': status,
            'request_type': request_type,
            'is_redirect': is_redirect,
            'location': location,
            'is_ajax': is_ajax,
            'is_form': is_form,
            'content_type': content_type,
            'cookies': cookies,
            'key_headers': {
                'user_agent': headers.get('user-agent', ''),
                'referer': headers.get('referer', ''),
                'origin': headers.get('origin', ''),
                'accept': headers.get('accept', ''),
            },
            'timings': timings,
            'timestamp': entry.get('startedDateTime', ''),
        }
        
        navigation_steps.append(step)
    
    return navigation_steps

def analyze_oauth_flow(navigation_steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze OAuth flow patterns"""
    oauth_steps = []
    auth0_steps = []
    login_steps = []
    
    for step in navigation_steps:
        if step['request_type'] == 'auth0':
            auth0_steps.append(step)
        elif step['request_type'] == 'login':
            login_steps.append(step)
        elif 'oauth' in step['url'].lower() or 'authorize' in step['url'].lower():
            oauth_steps.append(step)
    
    return {
        'oauth_steps': oauth_steps,
        'auth0_steps': auth0_steps,
        'login_steps': login_steps,
        'total_auth_requests': len(auth0_steps) + len(oauth_steps)
    }

def print_navigation_summary(navigation_steps: List[Dict[str, Any]]):
    """Print a summary of the navigation flow"""
    print("=" * 80)
    print("HAR FILE NAVIGATION FLOW ANALYSIS")
    print("=" * 80)
    
    # Group by request type
    by_type = {}
    for step in navigation_steps:
        req_type = step['request_type']
        if req_type not in by_type:
            by_type[req_type] = []
        by_type[req_type].append(step)
    
    print(f"\nTotal requests: {len(navigation_steps)}")
    print(f"Request types: {', '.join(by_type.keys())}")
    
    # Show key navigation steps
    print("\n" + "=" * 50)
    print("KEY NAVIGATION STEPS")
    print("=" * 50)
    
    for i, step in enumerate(navigation_steps[:20]):  # First 20 steps
        status_icon = "🔄" if step['is_redirect'] else "📄"
        ajax_icon = "⚡" if step['is_ajax'] else ""
        form_icon = "📝" if step['is_form'] else ""
        
        print(f"{i+1:2d}. {status_icon}{ajax_icon}{form_icon} {step['method']} {step['status']} | {step['request_type']:12} | {step['hostname']:20} | {step['path']}")
        
        if step['is_redirect'] and step['location']:
            print(f"     └─ Redirects to: {step['location']}")
        
        if step['is_form']:
            print(f"     └─ Form submission")
        
        if step['is_ajax']:
            print(f"     └─ AJAX request")

def print_oauth_analysis(oauth_analysis: Dict[str, Any]):
    """Print OAuth flow analysis"""
    print("\n" + "=" * 50)
    print("OAUTH FLOW ANALYSIS")
    print("=" * 50)
    
    print(f"OAuth-related requests: {oauth_analysis['total_auth_requests']}")
    print(f"Auth0 domain requests: {len(oauth_analysis['auth0_steps'])}")
    print(f"Login page requests: {len(oauth_analysis['login_steps'])}")
    
    if oauth_analysis['auth0_steps']:
        print("\nAuth0 domain requests:")
        for step in oauth_analysis['auth0_steps']:
            print(f"  - {step['method']} {step['status']} | {step['path']}")
    
    if oauth_analysis['oauth_steps']:
        print("\nOAuth-specific requests:")
        for step in oauth_analysis['oauth_steps']:
            print(f"  - {step['method']} {step['status']} | {step['path']}")

def print_cookie_analysis(navigation_steps: List[Dict[str, Any]]):
    """Print cookie usage analysis"""
    print("\n" + "=" * 50)
    print("COOKIE ANALYSIS")
    print("=" * 50)
    
    all_cookies = set()
    cookie_evolution = []
    
    for step in navigation_steps:
        if step['cookies']:
            step_cookies = set(step['cookies'].keys())
            all_cookies.update(step_cookies)
            
            if step_cookies:
                cookie_evolution.append({
                    'step': len(cookie_evolution) + 1,
                    'url': step['url'],
                    'cookies': step_cookies,
                    'new_cookies': step_cookies - (set().union(*[c['cookies'] for c in cookie_evolution]) if cookie_evolution else set())
                })
    
    print(f"Total unique cookies used: {len(all_cookies)}")
    print(f"Cookie names: {', '.join(sorted(all_cookies))}")
    
    if cookie_evolution:
        print("\nCookie evolution:")
        for evo in cookie_evolution[:10]:  # First 10 steps with cookies
            new_cookies = evo['new_cookies']
            new_indicator = f" (NEW: {', '.join(new_cookies)})" if new_cookies else ""
            print(f"  Step {evo['step']}: {len(evo['cookies'])} cookies{new_indicator}")
            print(f"    URL: {evo['url']}")

def print_script_comparison():
    """Print what our script is currently doing for comparison"""
    print("\n" + "=" * 50)
    print("OUR SCRIPT BEHAVIOR (for comparison)")
    print("=" * 50)
    
    print("Current script flow:")
    print("1. GET https://www.three.co.uk/login")
    print("2. JavaScript render() - waits for redirects")
    print("3. Check if on auth.three.co.uk domain")
    print("4. If not on auth.three.co.uk: ABORT (no clicking)")
    print("5. If on auth.three.co.uk: Fill form and submit")
    print("6. Test authentication with API call")
    
    print("\nKey differences to investigate:")
    print("- Does HAR show intermediate redirects we're missing?")
    print("- Does HAR show specific CTAs being clicked?")
    print("- Does HAR show different initial URLs?")
    print("- Does HAR show cookie requirements we're not meeting?")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 analyze_har.py <har_file_path>")
        print("Example: python3 analyze_har.py ~/Downloads/www.three.co.uk.har")
        sys.exit(1)
    
    har_path = sys.argv[1]
    
    print(f"Analyzing HAR file: {har_path}")
    
    # Parse HAR file
    har_data = parse_har_file(har_path)
    if not har_data:
        print("Failed to parse HAR file")
        sys.exit(1)
    
    # Extract navigation flow
    navigation_steps = extract_navigation_flow(har_data)
    if not navigation_steps:
        print("No navigation steps found in HAR file")
        sys.exit(1)
    
    # Analyze OAuth flow
    oauth_analysis = analyze_oauth_flow(navigation_steps)
    
    # Print analysis
    print_navigation_summary(navigation_steps)
    print_oauth_analysis(oauth_analysis)
    print_cookie_analysis(navigation_steps)
    print_script_comparison()
    
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
