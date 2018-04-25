#!/usr/bin/env python3
# -*- coding:Utf-8 -*-

import argparse
import traceback
import requests
import re

from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning

PROXY = False
STANDARD_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def fuzz_user_agent(url, wordlist_path, threads):
    headers = requests.utils.default_headers()

    # Default response
    headers.update({'User-Agent': STANDARD_UA})

    standard = requests.get(url, headers=headers)
    standard_source = re.sub(re.compile('.*' + re.escape(STANDARD_UA) + '.*\n'), '', standard.text, count=1)

    with open(wordlist_path) as wordlist:
        # Fuzz
        for word in wordlist:
            user_agent = word.strip()
            headers.update({'User-Agent': user_agent})

            user_agent = word.strip()

            fuzzed = requests.get(url, headers=headers)
            # fuzzed_source = re.sub(re.compile('.*' + re.escape(user_agent) + '.*\n'), '', fuzzed.text, count=1)

            # if standard_source != fuzzed_source and (len(standard.text) - len(STANDARD_UA.strip())) != (len(fuzzed.text) - len(user_agent.strip())):
            if (len(standard.text) - len(STANDARD_UA.strip())) != (len(fuzzed.text) - len(user_agent.strip())):
                print('{url} (UA: {ua})'.format(url=url, ua=user_agent))

def parse_args():
    """Arguments parsing."""
    parser = argparse.ArgumentParser(
        description='JAWFT - Just another web fuzzing tool'
    )
    parser.add_argument('-w', '--wordlist',
                        type=str,
                        default='/usr/share/wordlists/rockyou.txt',
                        help='path to wordlist')
    parser.add_argument('-u', '--url',
                        type=str,
                        required=True,
                        help='URL to website')
    parser.add_argument('-t', '--threads',
                        type=int,
                        default=200,
                        help='Max threads')
    args = parser.parse_args()
    return args

def main():
    """Fuzzing main function."""
    try:
        # Arguments parsing
        args = parse_args()

        # Perform UA fuzzing
        fuzz_user_agent(args.url, args.wordlist, args.threads)
    except (ValueError, TypeError, OSError) as exception_:
        print(traceback.format_exc())
        print(exception_)

# Runtime processor
if __name__ == '__main__':
    main()
