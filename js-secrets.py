#!/usr/bin/env python3

import requests
import re
import argparse
import json
import os
import sys
import urllib3
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize Colorama
init(autoreset=True)

# Fix Windows console encoding
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

secret_patterns = {}

def print_banner():
    banner = f"""
{Fore.CYAN}    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║  {Fore.YELLOW} ▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌ {Fore.CYAN}    ║
    ║  {Fore.YELLOW} ▐  {Fore.WHITE}     ██╗███████╗      ███████╗███████╗ ██████╗{Fore.YELLOW}         ▌ {Fore.CYAN}    ║
    ║  {Fore.YELLOW} ▐  {Fore.WHITE}     ██║██╔════╝      ██╔════╝██╔════╝██╔════╝{Fore.YELLOW}         ▌ {Fore.CYAN}    ║
    ║  {Fore.YELLOW} ▐  {Fore.WHITE}     ██║███████╗█████╗███████╗█████╗  ██║     {Fore.YELLOW}         ▌ {Fore.CYAN}    ║
    ║  {Fore.YELLOW} ▐  {Fore.WHITE}██   ██║╚════██║╚════╝╚════██║██╔══╝  ██║     {Fore.YELLOW}         ▌ {Fore.CYAN}    ║
    ║  {Fore.YELLOW} ▐  {Fore.WHITE}╚█████╔╝███████║      ███████║███████╗╚██████╗{Fore.YELLOW}         ▌ {Fore.CYAN}    ║
    ║  {Fore.YELLOW} ▐  {Fore.WHITE} ╚════╝ ╚══════╝      ╚══════╝╚══════╝ ╚═════╝{Fore.YELLOW}         ▌ {Fore.CYAN}    ║
    ║  {Fore.YELLOW} ▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌ {Fore.CYAN}    ║
    ║                                                                   ║
    ║  {Fore.GREEN}  ░▒▓ JavaScript Secret Scanner ▓▒░{Fore.CYAN}                              ║
    ║  {Fore.WHITE}  Extract API keys, tokens & credentials from JS files{Fore.CYAN}           ║
    ║                                                                   ║
    ║  {Fore.MAGENTA}  Author:{Fore.WHITE} buggedout{Fore.CYAN}                                              ║
    ║  {Fore.MAGENTA}  Version:{Fore.WHITE} 2.0{Fore.CYAN}                                                   ║
    ║  {Fore.MAGENTA}  GitHub:{Fore.WHITE} github.com/buggedout-1/js-secrets{Fore.CYAN}                      ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
    print(banner)

def load_patterns(pattern_file):
    global secret_patterns
    try:
        with open(pattern_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue
            # Skip lines that don't look like pattern definitions
            if not line.startswith("'") and not line.startswith('"'):
                continue
            line = line.rstrip(',')
            # Find the pattern name (between quotes) and value (after the colon)
            # Pattern format: 'Name': r'regex'
            match = re.match(r'^[\'"](.+?)[\'"]\s*:\s*(.+)$', line)
            if match:
                key = match.group(1)
                value_str = match.group(2).strip()
                try:
                    value = eval(value_str, {'re': re})
                    secret_patterns[key] = value
                except Exception as e:
                    print(Fore.YELLOW + f"[!] Error parsing pattern '{key}': {e}")
    except Exception as e:
        print(Fore.RED + f"[!] Error loading pattern file: {e}")
        sys.exit(1)

    print(Fore.CYAN + f"[*] Loaded {len(secret_patterns)} patterns.")

# Generic secret keywords to search for (key-value extraction)
# These will extract "keyword": "value" or keyword = "value" patterns
GENERIC_SECRET_KEYWORDS = [
    # API Keys
    'apikey', 'api_key', 'api-key', 'apiKey',
    'api_secret', 'apisecret', 'apiSecret', 'api-secret',

    # Tokens
    'token', 'access_token', 'accesstoken', 'accessToken', 'access-token',
    'auth_token', 'authtoken', 'authToken', 'auth-token',
    'bearer_token', 'bearertoken', 'bearerToken', 'bearer-token',
    'refresh_token', 'refreshtoken', 'refreshToken', 'refresh-token',
    'id_token', 'idtoken', 'idToken', 'id-token',
    'session_token', 'sessiontoken', 'sessionToken', 'session-token',

    # Secrets
    'secret', 'secret_key', 'secretkey', 'secretKey', 'secret-key',
    'client_secret', 'clientsecret', 'clientSecret', 'client-secret',
    'app_secret', 'appsecret', 'appSecret', 'app-secret',

    # Passwords
    'password', 'passwd', 'pwd', 'pass',

    # Keys
    'private_key', 'privatekey', 'privateKey', 'private-key',
    'public_key', 'publickey', 'publicKey', 'public-key',
    'encryption_key', 'encryptionkey', 'encryptionKey', 'encryption-key',
    'signing_key', 'signingkey', 'signingKey', 'signing-key',

    # Service-specific keywords
    'github_token', 'githubtoken', 'githubToken', 'github-token',
    'gitlab_token', 'gitlabtoken', 'gitlabToken', 'gitlab-token',
    'aws_key', 'awskey', 'awsKey', 'aws-key',
    'aws_secret', 'awssecret', 'awsSecret', 'aws-secret',
    'stripe_key', 'stripekey', 'stripeKey', 'stripe-key',
    'slack_token', 'slacktoken', 'slackToken', 'slack-token',
    'discord_token', 'discordtoken', 'discordToken', 'discord-token',
    'firebase_key', 'firebasekey', 'firebaseKey', 'firebase-key',
    'google_key', 'googlekey', 'googleKey', 'google-key',
    'openai_key', 'openaikey', 'openaiKey', 'openai-key',
    'database_url', 'databaseurl', 'databaseUrl', 'database-url',
    'db_password', 'dbpassword', 'dbPassword', 'db-password',
    'redis_url', 'redisurl', 'redisUrl', 'redis-url',
    'mongo_uri', 'mongouri', 'mongoUri', 'mongo-uri',

    # Credentials
    'credentials', 'creds', 'auth', 'authorization',
    'client_id', 'clientid', 'clientId', 'client-id',
    'app_id', 'appid', 'appId', 'app-id',
    'consumer_key', 'consumerkey', 'consumerKey', 'consumer-key',
    'consumer_secret', 'consumersecret', 'consumerSecret', 'consumer-secret',
]

# False positive indicators - skip matches containing these
FALSE_POSITIVE_INDICATORS = [
    'cdn-cgi',                    # Cloudflare challenge scripts
    'challenge-platform',         # Cloudflare challenge tokens
    'cloudflare',                 # Cloudflare related
    '__WEBPACK__',                # Webpack internal vars
    'sourceMappingURL',           # Source maps
    'function(',                  # JS function definitions
    '.prototype',                 # JS prototype chains
    'Object.defineProperty',      # JS internals
    '===',                        # Comparison operators
    'return ',                    # Function returns
    'undefined',                  # JS undefined
    'null',                       # JS null
    '.exec)',                     # Regex exec
    'RegExp',                     # RegExp constructor
]

def is_false_positive(secret_type, match, context=""):
    """Check if a match is likely a false positive"""
    match_str = str(match) if not isinstance(match, str) else match

    # Check for false positive indicators
    for indicator in FALSE_POSITIVE_INDICATORS:
        if indicator.lower() in match_str.lower():
            return True
        if indicator.lower() in context.lower():
            return True

    # Specific checks per secret type
    if 'Telegram' in secret_type:
        # Real Telegram tokens always start with digits and have 'AA' after colon
        if not re.match(r'^\d{9,10}:AA', match_str):
            return True

    if 'Azure SAS' in secret_type:
        # Must have proper SAS format with date
        if 'sv=' not in match_str or not re.search(r'\d{4}-\d{2}-\d{2}', match_str):
            return True

    if 'Generic' in secret_type:
        # Generic patterns are often false positives in minified JS
        # Require at least some context suggesting it's a real secret
        if len(match_str) < 20:
            return True
        # Skip if looks like minified variable names
        if re.match(r'^[a-z]{1,3}$', match_str):
            return True

    return False

def extract_generic_keywords(page_content):
    """
    Extract key-value pairs based on generic secret keywords.
    Matches patterns like:
    - "apikey": "value"
    - apikey = "value"
    - apikey: "value"
    - 'api_key': 'value'
    """
    generic_secrets = {}

    # Values that are clearly not secrets
    SKIP_VALUES = [
        'null', 'undefined', 'true', 'false', 'none', '',
        '0', '1', 'test', 'example', 'placeholder', 'your-',
        'xxx', 'yyy', 'zzz', 'abc', '123', 'TODO', 'FIXME',
        'process.env', 'window.', 'document.', 'this.',
    ]

    for keyword in GENERIC_SECRET_KEYWORDS:
        # Build regex patterns for different formats:
        # 1. JSON style: "keyword": "value" or 'keyword': 'value'
        # 2. JS assignment: keyword = "value" or keyword: "value"
        # 3. Object property: keyword: "value"
        patterns = [
            # "keyword": "value" or 'keyword': 'value' (JSON/object style)
            rf'["\']?{re.escape(keyword)}["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            # keyword="value" (attribute style)
            rf'{re.escape(keyword)}\s*=\s*["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            try:
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                for match in matches:
                    value = match.strip() if isinstance(match, str) else str(match).strip()

                    # Skip empty or too short values
                    if len(value) < 8:
                        continue

                    # Skip common non-secret values
                    skip = False
                    for skip_val in SKIP_VALUES:
                        if value.lower().startswith(skip_val.lower()):
                            skip = True
                            break
                    if skip:
                        continue

                    # Skip if value looks like code/function
                    if any(x in value for x in ['function', 'return', '=>', '()', '{}', '[]']):
                        continue

                    # Skip if value is a URL path (not a full URL with credentials)
                    if value.startswith('/') and '://' not in value:
                        continue

                    # Create category name
                    category = f"Generic ({keyword})"

                    if category not in generic_secrets:
                        generic_secrets[category] = []

                    # Store as "keyword": "value" format
                    key_value_pair = f'"{keyword}": "{value}"'
                    if key_value_pair not in generic_secrets[category]:
                        generic_secrets[category].append(key_value_pair)

            except Exception:
                pass

    return generic_secrets


def extract_secrets(page_content):
    secrets_found = {}

    # First: Pattern-based extraction (existing behavior)
    for secret_type, pattern in secret_patterns.items():
        try:
            matches = re.findall(pattern, page_content)
            if matches:
                # Filter out false positives
                filtered_matches = []
                for match in matches:
                    # Get some context around the match for better FP detection
                    match_str = str(match) if not isinstance(match, str) else match
                    try:
                        match_pos = page_content.find(match_str)
                        if match_pos != -1:
                            context_start = max(0, match_pos - 50)
                            context_end = min(len(page_content), match_pos + len(match_str) + 50)
                            context = page_content[context_start:context_end]
                        else:
                            context = ""
                    except:
                        context = ""

                    if not is_false_positive(secret_type, match, context):
                        filtered_matches.append(match)

                if filtered_matches:
                    # Deduplicate matches
                    secrets_found[secret_type] = list(set(filtered_matches))
        except Exception as e:
            print(Fore.YELLOW + f"[!] Skipping pattern {secret_type}: {e}")

    # Second: Generic keyword-based extraction (NEW)
    generic_secrets = extract_generic_keywords(page_content)
    for category, values in generic_secrets.items():
        if category not in secrets_found:
            secrets_found[category] = values
        else:
            secrets_found[category].extend(values)
            secrets_found[category] = list(set(secrets_found[category]))

    return secrets_found

def scan_url(url, current_index, total_urls):
    try:
        sys.stdout.write(f"\rLoading URL {current_index} of {total_urls}...")
        sys.stdout.flush()

        response = requests.get(url, timeout=15, verify=False)
        if response.status_code == 200:
            page_content = response.text
            secrets = extract_secrets(page_content)
            if secrets:
                return {
                    'url': url,
                    'secrets': secrets
                }
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"\n[!] Error fetching {url}: {e}")
    return None

def save_to_json_immediately(results, output_file='secrets.json'):
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            all_data = json.load(f)
    else:
        all_data = []

    all_data.extend(results)
    with open(output_file, 'w') as f:
        json.dump(all_data, f, indent=4)
    print(Fore.GREEN + f"\n[*] Results saved to secrets.json.")

def process_urls_concurrently_in_batches(url_list, max_workers=8, batch_size=1000):
    results = []
    total_urls = len(url_list)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(scan_url, url, index, total_urls): (url, index)
                         for index, url in enumerate(url_list, start=1)}

        for future in as_completed(future_to_url):
            url, index = future_to_url[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
                if len(results) >= batch_size:
                    save_to_json_immediately(results)
                    results = []
            except Exception as e:
                print(Fore.RED + f"Error processing {url}: {e}")

    if results:
        save_to_json_immediately(results)

    print(Fore.GREEN + "[*] All results processed and saved.")

def process_urls_chunked(url_list, max_workers=8, chunk_size=10000):
    for i in range(0, len(url_list), chunk_size):
        chunk = url_list[i:i+chunk_size]
        process_urls_concurrently_in_batches(chunk, max_workers)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Extract secrets from a list of URLs.")
    parser.add_argument('-l', '--list', type=str, help="Path to a file containing a list of URLs", required=False)
    parser.add_argument('-w', '--workers', type=int, help="Number of workers (threads) to use", default=8)
    parser.add_argument('-p', '--patterns', type=str, help="Path to a pattern file", required=True)

    args = parser.parse_args()

    if args.patterns:
        load_patterns(args.patterns)

    if args.list:
        with open(args.list, 'r') as file:
            urls = file.readlines()
        urls = [url.strip() for url in urls]
        process_urls_chunked(urls, max_workers=args.workers)
    else:
        print(Fore.RED + "Please provide a URL list file using the -l option.")
        sys.exit(1)

if __name__ == '__main__':
    main()
