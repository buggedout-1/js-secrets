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

from multiprocessing import Process, Queue as MPQueue

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

# Known public keys / non-secret patterns to skip
PUBLIC_KEY_PATTERNS = [
    r'^6L[a-zA-Z0-9_-]{20,40}$',  # Google reCAPTCHA site keys (public) - various lengths
    # Note: Stripe publishable keys (pk_test_, pk_live_) are NOT filtered
    # because while they're technically "public", finding them in JS files
    # can still indicate exposed API integration that should be audited
]

# Placeholder/test/example values to skip
PLACEHOLDER_INDICATORS = [
    'your-', 'your_', 'your ',     # Placeholder indicators
    'replace', 'change-me', 'changeme',
    'example', 'sample', 'dummy', 'fake',
    'test_', 'test-', 'testing',
    'placeholder', 'todo', 'fixme',
    'xxx', 'yyy', 'zzz',
    'enter-', 'enter_', 'insert-', 'insert_',
    'my-api', 'my_api', 'myapi',
    '<your', '[your', '{your',
    'not_a_real', 'not-a-real', 'notareal',  # Placeholder passwords
    'bearer_token', 'api_token', 'api_key_here',  # Common placeholders
    'username:password',           # MongoDB/URL placeholder
]

# Values that are EXACT matches to skip (not substring)
EXACT_FALSE_POSITIVES = [
    # Fetch API credentials options
    'include', 'omit', 'same-origin',
    # HTML input types
    'text', 'password',
    # Common non-secret values
    'true', 'false', 'null', 'undefined',
    # Common JS values
    'get', 'post', 'put', 'delete', 'patch',
    # Common UI labels (English)
    'username', 'password', 'login', 'logout', 'sign in', 'sign out',
    'current password', 'new password', 'save password', 'change password',
    'confirm password', 'manual login', 'login page', 'demo account',
    'login via google', 'forgot password',
    # German
    'passwort', 'benutzername', 'anmelden', 'abmelden', 'neues passwort',
    'aktuelles passwort', 'passwort ändern', 'passwort speichern',
    # French
    'mot de passe', 'nom d\'utilisateur', 'connexion', 'nouveau mot de passe',
    # Spanish
    'contraseña', 'nombre de usuario', 'iniciar sesión', 'nueva contraseña',
    'contraseña actual',
    # Italian
    'password attuale', 'nuova password', 'nome utente', 'salva password',
    # Portuguese
    'senha', 'senha atual', 'nova senha', 'nome de usuário', 'salvar senha',
    # Russian (transliterated for matching)
    'пароль', 'имя пользователя', 'новый пароль', 'текущий пароль',
    # Japanese common
    'パスワード', 'ユーザ名', '新しいパスワード', '現在のパスワード',
    # German single-word UI labels
    'einloggen', 'anmelden', 'abmelden', 'registrieren',
    # Italian single-word UI labels
    'accedi', 'accesso', 'entra', 'esci',
    # French single-word UI labels
    'connexion', 'déconnexion', 'connecter',
    # Spanish single-word UI labels
    'ingresar', 'salir', 'entrar',
    # Portuguese single-word UI labels
    'entrar', 'sair', 'acessar',
]

# UI text patterns - if match contains these, it's likely UI text not a credential
UI_TEXT_INDICATORS = [
    # Sentence indicators (spaces + common words)
    ' the ', ' a ', ' an ', ' is ', ' are ', ' was ', ' were ',
    ' you ', ' your ', ' our ', ' their ', ' its ',
    ' can ', ' cannot ', ' must ', ' should ', ' would ', ' could ',
    ' have ', ' has ', ' had ', ' been ', ' being ',
    ' this ', ' that ', ' these ', ' those ',
    ' will ', ' won\'t ', ' don\'t ', ' doesn\'t ', ' didn\'t ',
    ' not ', ' no ', ' yes ',
    ' please ', ' enter ', ' click ', ' select ', ' choose ',
    ' invalid ', ' incorrect ', ' error ', ' failed ', ' success ',
    ' too short', ' too long', ' required', ' optional',
    ' characters', ' between ', ' at least', ' minimum', ' maximum',
    # Multi-language sentence patterns
    ' le ', ' la ', ' les ', ' un ', ' une ', ' des ',  # French
    ' der ', ' die ', ' das ', ' ein ', ' eine ',       # German
    ' el ', ' los ', ' las ', ' un ', ' una ',          # Spanish
    ' il ', ' lo ', ' gli ', ' un ', ' una ',           # Italian
    ' o ', ' os ', ' as ', ' um ', ' uma ',             # Portuguese
    # Common UI verbs/phrases
    'forgot', 'reset', 'change', 'update', 'confirm', 'verify',
    'log in', 'sign in', 'sign out',
    # Error messages
    'do not match', 'does not match', 'don\'t match',
    'we cannot', 'you cannot', 'cannot be',
    'incorrect',
    # API key error messages
    'have not added', 'not added', 'no ha añadido', 'non hai aggiunto',
    'hast keinen', 'não adicionou', 'не добавили',
]

# Sequential/obviously fake patterns (regex)
FAKE_PATTERN_REGEXES = [
    r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',  # UUID format
    r'^(.)\1{10,}$',                              # Repeated single character
    r'^(..)\1{5,}$',                              # Repeated two characters
    r'^x{10,}$',                                  # Just x's
]

# Sequences that indicate test/fake data
FAKE_SEQUENCES = [
    '1234567890',           # Sequential numbers
    '0123456789',           # Sequential numbers
    'abcdefghij',           # Sequential lowercase
    'abcdefghijklmnop',     # Longer sequential lowercase
    'abcdefghijklmnopqrstuvwxyz',  # Full alphabet
    'ABCDEFGHIJ',           # Sequential uppercase
    'ABCDEFGHIJKLMNOP',     # Longer sequential uppercase
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',  # Full uppercase alphabet
]

def is_false_positive(secret_type, match, context=""):
    """Check if a match is likely a false positive"""
    match_str = str(match) if not isinstance(match, str) else match
    match_lower = match_str.lower()

    # Check for known public key patterns (not secrets)
    for pattern in PUBLIC_KEY_PATTERNS:
        if re.match(pattern, match_str):
            return True

    # Check for placeholder/test/example indicators
    # Skip this check for Stripe patterns (pk_test_ is a legitimate Stripe test key format, not a placeholder)
    if 'Stripe' not in secret_type:
        for indicator in PLACEHOLDER_INDICATORS:
            if indicator.lower() in match_lower:
                return True

    # Check for sequential/fake patterns (regex)
    for pattern in FAKE_PATTERN_REGEXES:
        if re.match(pattern, match_lower, re.IGNORECASE):
            return True

    # Check for fake sequences in the value
    for seq in FAKE_SEQUENCES:
        if seq.lower() in match_lower:
            return True

    # Check for false positive indicators in context
    # Skip context check for JSON and Generic credential patterns - these are real hardcoded creds
    # and often appear right next to webpack code like "function("
    for indicator in FALSE_POSITIVE_INDICATORS:
        if indicator.lower() in match_lower:
            return True
        # Skip context filtering for JSON, Generic, and Stripe patterns
        # (JSON/Generic are often in minified webpack bundles, Stripe keys are often in function calls like window.Stripe("pk_..."))
        if 'JSON' not in secret_type and 'Generic' not in secret_type and 'Stripe' not in secret_type:
            if indicator.lower() in context.lower():
                return True

    # Skip if value is all same case letters followed by all numbers (like abcdefgh12345678)
    # Exception: Don't filter JSON credential patterns - these are real hardcoded passwords
    if 'JSON' not in secret_type:
        if re.match(r'^[a-z]{6,}[0-9]{6,}$', match_lower) or re.match(r'^[0-9]{6,}[a-z]{6,}$', match_lower):
            # But allow if it has mixed case or special chars (real tokens usually do)
            if match_str == match_lower or match_str == match_str.upper():
                return True

    # Skip very simple patterns
    if re.match(r'^([a-f0-9]{8})+$', match_lower) and len(set(match_lower)) < 10:
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
        # But allow shorter matches for password/credential patterns
        is_password_type = any(x in secret_type.lower() for x in ['password', 'passwd', 'pwd', 'pass', 'credential', 'login', 'username', 'demo'])
        min_length = 3 if is_password_type else 20

        if len(match_str) < min_length:
            return True
        # Skip if looks like minified variable names
        if re.match(r'^[a-z]{1,3}$', match_str):
            return True

        # === ADDITIONAL GENERIC PATTERN FILTERS ===

        # Skip exact matches of common non-credential values
        if match_lower in EXACT_FALSE_POSITIVES:
            return True

        # Skip CSS selectors (start with . or #)
        if match_str.startswith('.') or match_str.startswith('#'):
            return True

        # Skip URL paths (start with /)
        if match_str.startswith('/'):
            return True

        # Skip if contains UI text indicators (likely a sentence/label)
        for indicator in UI_TEXT_INDICATORS:
            if indicator.lower() in match_lower:
                return True

        # Skip any string with spaces - real hardcoded credentials don't have spaces
        # (e.g. "Cambia password", "Password vergessen?" are UI text, not credentials)
        if ' ' in match_str:
            return True

        # Skip strings with hyphens that look like UI labels (e.g. "Login-Seite", "Demo-Account")
        if '-' in match_str and any(w[0].isupper() for w in match_str.split('-') if w):
            return True

        # Skip strings that are mostly non-ASCII (likely UI text in other languages)
        non_ascii_count = sum(1 for c in match_str if ord(c) > 127)
        if non_ascii_count > len(match_str) * 0.3:  # More than 30% non-ASCII
            return True

        # Skip common localization key patterns
        if match_str.startswith('feature.') or match_str.startswith('error.') or match_str.startswith('label.'):
            return True

        # Skip if ends with common file extensions
        if re.search(r'\.(js|css|html|json|txt|md|yml|yaml|xml|png|jpg|svg)$', match_lower):
            return True

        # Skip URLs
        if match_str.startswith('http://') or match_str.startswith('https://'):
            return True

    # Skip "BEARER_TOKEN" and similar placeholder patterns for Bearer Token type
    if 'Bearer' in secret_type:
        if match_str.upper() == match_str and '_' in match_str:  # ALL_CAPS_WITH_UNDERSCORES
            return True

    return False


def extract_secrets(page_content):
    """Extract secrets using external patterns only.
    Returns tuple: (secrets_found, generic_found)
    - secrets_found: specific patterns -> secrets.json
    - generic_found: Generic:* patterns -> passwords.json
    """
    secrets_found = {}
    generic_found = {}

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
                    unique_matches = list(set(filtered_matches))

                    # Route to appropriate output based on pattern type
                    if secret_type.startswith('Generic:'):
                        # Remove "Generic:" prefix for cleaner output
                        clean_type = secret_type.replace('Generic:', '')
                        generic_found[clean_type] = unique_matches
                    else:
                        secrets_found[secret_type] = unique_matches
        except Exception as e:
            print(Fore.YELLOW + f"[!] Skipping pattern {secret_type}: {e}")

    return secrets_found, generic_found

def _extract_worker(page_content, result_queue):
    """Worker for multiprocessing timeout."""
    try:
        result = extract_secrets(page_content)
        result_queue.put(result)
    except:
        result_queue.put(None)

def run_extract_with_timeout(page_content, timeout=15):
    """Run extract_secrets with timeout - kills if stuck."""
    result_queue = MPQueue()
    process = Process(target=_extract_worker, args=(page_content, result_queue), daemon=True)
    process.start()
    process.join(timeout=timeout)

    if process.is_alive():
        process.terminate()
        process.join(1)
        return None

    try:
        return result_queue.get_nowait()
    except:
        return None

def scan_url(url, current_index, total_urls):
    try:
        sys.stdout.write(f"\rLoading URL {current_index} of {total_urls}...")
        sys.stdout.flush()

        response = requests.get(url, timeout=15, verify=False)
        if response.status_code == 200:
            page_content = response.text

            # Run extract_secrets with 15 sec timeout
            result = run_extract_with_timeout(page_content, timeout=15)
            if result is None:
                return None
            secrets, generic = result

            result = {'url': url}
            has_findings = False

            if secrets:
                result['secrets'] = secrets
                has_findings = True
            if generic:
                result['generic'] = generic
                has_findings = True

            if has_findings:
                return result
    except requests.exceptions.RequestException:
        pass
    return None

def save_results(results):
    """Save results to secrets.json and passwords.json separately."""
    secrets_data = []
    passwords_data = []

    for result in results:
        url = result.get('url', '')

        # Handle specific secrets -> secrets.json
        if result.get('secrets'):
            secrets_data.append({
                'url': url,
                'secrets': result['secrets']
            })

        # Handle generic patterns -> passwords.json
        if result.get('generic'):
            passwords_data.append({
                'url': url,
                'passwords': result['generic']
            })

    # Save to secrets.json
    if secrets_data:
        if os.path.exists('secrets.json'):
            with open('secrets.json', 'r') as f:
                existing = json.load(f)
        else:
            existing = []
        existing.extend(secrets_data)
        with open('secrets.json', 'w') as f:
            json.dump(existing, f, indent=4)
        print(Fore.GREEN + f"\n[*] Results saved to secrets.json.")

    # Save to passwords.json
    if passwords_data:
        if os.path.exists('passwords.json'):
            with open('passwords.json', 'r') as f:
                existing = json.load(f)
        else:
            existing = []
        existing.extend(passwords_data)
        with open('passwords.json', 'w') as f:
            json.dump(existing, f, indent=4)
        print(Fore.CYAN + f"[*] Generic patterns saved to passwords.json.")

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
                    save_results(results)
                    results = []
            except Exception as e:
                print(Fore.RED + f"Error processing {url}: {e}")

    if results:
        save_results(results)

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
