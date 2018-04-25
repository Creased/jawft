#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import traceback
import requests
import sys
import re
import sys
import codecs
import io

is_py2 = sys.version[0] == '2'
if is_py2:
    from Queue import Queue
    import httplib
    from urlparse import urlparse
else:
    from queue import Queue
    import http.client as httplib
    from urllib.parse import urlparse

from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning

DEBUG = False
STANDARD_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class UAFuzz(object):
    """Perform UA fuzzing."""
    def __init__(self, index, queue, url, headers, standard_size, standard_source):
        self.index = index
        self.queue = queue
        self.url = url
        self.headers = headers
        self.standard_size = standard_size
        self.standard_source = standard_source

    def run(self):
        while True:
            #get your data off the queue, and do some work
            self.user_agent = str(self.queue.get(block=True))

            if DEBUG: print('Thread #{id}: {ua}'.format(id=self.index, ua=self.user_agent))

            print(self.user_agent)
            print(self.headers['User-Agent'])
            self.headers['User-Agent'] = self.user_agent

            connection = httplib.HTTPConnection(urlparse(self.url).hostname)
            connection.request(method='GET', url=self.url, body='', headers=self.headers)
            reponse = connection.getresponse()
            fuzzed = reponse.read().decode('utf-8')
            fuzzed_source = re.sub(re.compile('.*' + re.escape(self.user_agent) + '.*\n'), '', fuzzed, count=1)
            fuzzed_size = len(fuzzed) - len(self.user_agent)
            connection.close()

            if self.standard_source != fuzzed_source and self.standard_size != fuzzed_size:
            # if self.standard_size != fuzzed_size:
                print('Thread #{id}: {url} (UA: {ua})'.format(id=self.index, url=self.url, ua=self.user_agent))
                print(self.headers['User-Agent'])
                print(self.user_agent)

            self.queue.task_done()

def fuzz_user_agent(url, wordlist_path, threads_count):
    # Default headers
    headers = {'User-Agent': STANDARD_UA, 'Accept': 'text/plain'}

    connection = httplib.HTTPConnection(urlparse(url).hostname)
    connection.request(method='GET', url=url, body='', headers=headers)
    reponse = connection.getresponse()

    standard = reponse.read().decode('utf-8')
    standard_source = re.sub(re.compile('.*' + re.escape(STANDARD_UA) + '.*\n'), '', standard, count=1)
    standard_size = len(standard) - len(STANDARD_UA.strip())

    connection.close()


    queue = Queue()

    for index in range(1, threads_count + 1):
        worker = UAFuzz(index, queue, url, headers, standard_size, standard_source)
        worker_thread = Thread(target=worker.run)
        worker_thread.daemon = True
        worker_thread.start()

    try:
        with codecs.open(wordlist_path, encoding='utf-8', errors='strict', buffering=1) as wordlist:
            for word in wordlist:
                queue.put(word.strip())
        queue.join()
    except KeyboardInterrupt:
        sys.exit(1)

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
                        default=2,
                        help='threads')
    parser.add_argument('-d', '--debug',
                        action='store_true',
                        default=False,
                        help='Debug')
    args = parser.parse_args()
    return args

def main():
    """Fuzzing main function."""
    try:
        # Arguments parsing
        args = parse_args()
        global DEBUG
        DEBUG = args.debug

        # Perform UA fuzzing
        fuzz_user_agent(args.url, args.wordlist, args.threads)
    except (ValueError, TypeError, OSError) as exception_:
        print(traceback.format_exc())
        print(exception_)

# Runtime processor
if __name__ == '__main__':
    main()
