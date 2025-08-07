import aiohttp
import asyncio
import argparse
import os

# ANSI color codes for terminal
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

DEFAULT_WORDLIST = os.path.join("wordlists", "common.txt")
CONCURRENT_CONNECTIONS = 20

# Methods considered risky
RISKY_METHODS = ["PUT", "DELETE", "PATCH"]

async def fetch_status(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            return url, response.status
    except:
        return url, None

async def fetch_options(session, url):
    try:
        async with session.options(url, timeout=10) as response:
            allow = response.headers.get('Allow')
            return url, allow
    except:
        return url, None

async def scan(target, wordlist_path):
    connector = aiohttp.TCPConnector(limit=CONCURRENT_CONNECTIONS)
    async with aiohttp.ClientSession(connector=connector) as session:
        urls = []
        with open(wordlist_path, "r") as f:
            for line in f:
                path = line.strip()
                if not path or path.startswith("#"):
                    continue
                full_url = f"{target.rstrip('/')}/{path.lstrip('/')}"
                urls.append(full_url)

        print(f"[*] Loaded {len(urls)} paths from wordlist.")
        print("[*] Scanning for valid endpoints...")

        tasks = [fetch_status(session, url) for url in urls]
        responses = await asyncio.gather(*tasks)

        valid_urls = [url for url, status in responses if status and (200 <= status < 400)]

        print(f"[+] Found {len(valid_urls)} valid endpoints.")

        print("[*] Checking OPTIONS methods...")
        option_tasks = [fetch_options(session, url) for url in valid_urls]
        options_responses = await asyncio.gather(*option_tasks)

        for url, allow in options_responses:
            if allow:
                allow_methods = [method.strip().upper() for method in allow.split(',')]
                risky = any(method in RISKY_METHODS for method in allow_methods)

                if risky:
                    print(f"{RED}[!!] {url} supports risky methods: {allow}{RESET}")
                else:
                    print(f"{GREEN}[+] {url} supports methods: {allow}{RESET}")
            else:
                print(f"{YELLOW}[-] {url} returned no Allow header.{RESET}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MethodMisuse: Discover risky HTTP methods after directory fuzzing")
    parser.add_argument("-u", "--url", required=True, help="Target base URL")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="Path to wordlist (default: wordlists/common.txt)")
    args = parser.parse_args()

    if not os.path.isfile(args.wordlist):
        print(f"[!] Wordlist file not found: {args.wordlist}")
        exit(1)

    asyncio.run(scan(args.url, args.wordlist))
