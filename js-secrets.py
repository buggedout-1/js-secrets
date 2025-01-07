#!/usr/bin/env python3

import requests
import re
import argparse
import json
import os
import sys
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = r"""
 🅹🆂-🆂🅴🅲🆁🅴🆃🆂 
    """
    print(Fore.GREEN + banner)

def extract_secrets(page_content):
    # Define secret patterns (e.g., API keys, tokens, etc.)
    secret_patterns = {
        'API Token': r'(?i)\bAPI\s*Token\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
        'API Access Key': r'(?i)\bAPI\s*Access\s*Key\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
        'Bearer Token': r'(?i)\bBearer\s*[:=]?\s*[\'"]?([A-Za-z0-9_-]{32,})[\'"]?',
        # Add more patterns as needed
    }

    secrets_found = {}
    for secret_type, pattern in secret_patterns.items():
        matches = re.findall(pattern, page_content)
        if matches:
            secrets_found[secret_type] = matches
    return secrets_found

def scan_url(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            page_content = response.text
            secrets = extract_secrets(page_content)
            return {
                'url': url,
                'secrets': secrets
            }
    except requests.exceptions.RequestException:
        pass  # Skip silently if any request exception occurs

    return None  # Return None if the URL does not return a 200 OK or if there's an error

def save_to_json(results, output_file='secrets.json'):
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            all_data = json.load(f)
    else:
        all_data = []

    all_data.extend(results)
    
    with open(output_file, 'w') as f:
        json.dump(all_data, f, indent=4)

def process_urls(url_list):
    results = []
    for url in url_list:
        result = scan_url(url)
        if result:  # Only add to results if it's not None
            results.append(result)
    save_to_json(results)

def main():
    parser = argparse.ArgumentParser(description="Extract secrets from a list of URLs.")
    parser.add_argument('-l', '--list', type=str, help="Path to a file containing a list of URLs", required=False)

    args = parser.parse_args()

    if args.list:
        with open(args.list, 'r') as file:
            urls = file.readlines()
        urls = [url.strip() for url in urls]
        process_urls(urls)
    else:
        print(Fore.RED + "Please provide a URL list file using the -l option.")
        sys.exit(1)

if __name__ == '__main__':
    main()
