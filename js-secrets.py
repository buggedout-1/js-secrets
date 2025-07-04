#!/usr/bin/env python3

import requests
import re
import argparse
import json
import os
import sys
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize Colorama
init(autoreset=True)

secret_patterns = {}

def print_banner():
    banner = r"""
     ██╗███████╗      ███████╗███████╗ ██████╗██████╗ ███████╗████████╗███████╗
     ██║██╔════╝      ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝
     ██║███████╗█████╗███████╗█████╗  ██║     ██████╔╝█████╗     ██║   ███████╗
██   ██║╚════██║╚════╝╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   ╚════██║
╚█████╔╝███████║      ███████║███████╗╚██████╗██║  ██║███████╗   ██║   ███████║
 ╚════╝ ╚══════╝      ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝
                                                                               by buggedout
    """
    print(Fore.GREEN + banner)

def load_patterns(pattern_file):
    global secret_patterns
    try:
        with open(pattern_file, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if ':' not in line:
                continue
            line = line.strip().rstrip(',')
            key, value = line.split(':', 1)
            key = key.strip().strip('"').strip("'")
            value = eval(value.strip(), {'re': re})
            secret_patterns[key] = value
    except Exception as e:
        print(Fore.RED + f"[!] Error loading pattern file: {e}")
        sys.exit(1)

def extract_secrets(page_content):
    secrets_found = {}
    for secret_type, pattern in secret_patterns.items():
        try:
            matches = re.findall(pattern, page_content)
            if matches:
                secrets_found[secret_type] = matches
        except Exception as e:
            print(Fore.YELLOW + f"[!] Skipping pattern {secret_type}: {e}")
    return secrets_found

def scan_url(url, current_index, total_urls):
    try:
        sys.stdout.write(f"\rLoading URL {current_index} of {total_urls}...")
        sys.stdout.flush()
        
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            page_content = response.text
            secrets = extract_secrets(page_content)
            if secrets:
                return {
                    'url': url,
                    'secrets': secrets
                }
    except requests.exceptions.RequestException:
        pass
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
