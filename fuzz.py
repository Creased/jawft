#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import traceback
import threading
import argparse
import logging
import copy
import sys
import re
import io

is_py2 = sys.version[0] == '2'
if is_py2:
    import httplib
    from urlparse import urlparse
else:
    import http.client as httplib
    from urllib.parse import urlparse

DEBUG = False
STANDARD_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'

class Wordlist(object):
    """Simple thread-safe wordlist iterator."""
    def __init__(self, wordlist_path):
        try:
            self.wordlist = io.FileIO(wordlist_path, mode='r')
        except IOError as exception_:
            raise IOError("Error opening file. {}".format(exception_))
        else:
            self.wordlist.seek(0)
            self._opened = True

    def next(self):
        return (next(self.wordlist)).decode('utf-8').strip()

    def __next__(self):
        return self.next()

    def __iter__(self):
        return self

    def close(self):
        self.wordlist.close()
        self._opened = False

class UAFuzz(object):
    """Perform UA fuzzing."""
    def __init__(self, index, wordlist, url, headers, standard_size, standard_source):
        self.index = index
        self.wordlist = wordlist
        self.url = url
        self.headers = headers
        self.standard_size = standard_size
        self.standard_source = standard_source
        self.stop = False
        self.user_agent = headers['User-Agent']

    def run(self):
        # While there is UA left and we're not stopping
        while self.user_agent and not self.stop:
            try:
                # Iterate through shared and thread-safe FileIO object
                self.user_agent = self.wordlist.next()
            except StopIteration:
                # No more UA to process, stop this thread
                self.stop = True
            else:
                # Debug used to catch race condition:
                # COW mechanism or something else is causing race condition when we pass headers dict without doing deepcopy...
                if DEBUG: print('Thread #{id}: {ua}'.format(id=self.index, ua=self.user_agent))
                # if DEBUG: print('(bef) Thread #{id}: {ua}'.format(id=self.index, ua=self.user_agent))
                # if DEBUG: print('(bef) Thread #{id}: {ua}'.format(id=self.index, ua=self.headers['User-Agent']))

                # Update headers with custom User Agent (wordlist entry)
                self.headers['User-Agent'] = self.user_agent

                # Get response from the server (fuzzed User Agent)
                fuzzed_size, fuzzed_source = http_request(self.url, self.headers)

                # Remove reflected User Agent from source code
                fuzzed_source = re.sub(re.compile('.*' + re.escape(self.headers['User-Agent']) + '.*\n'), '', fuzzed_source, count=1)
                fuzzed_size = fuzzed_size - len(self.headers['User-Agent'].strip())

                # Check if the source code is different between response from standard and fuzzed User-Agent
                if self.standard_source != fuzzed_source and self.standard_size != fuzzed_size:
                    # Print User Agent that has made the source code change
                    print('{url} (UA: {ua})'.format(url=self.url, ua=self.user_agent))

                    # Another debug (may be used for race condition tracing purpose)
                    # if DEBUG: print('(af) Thread #{id}: {ua}'.format(id=self.index, ua=self.user_agent))
                    # if DEBUG: print('(af) Thread #{id}: {ua}'.format(id=self.index, ua=self.headers['User-Agent']))

    def terminate(self):
        # Terminate thread
        if DEBUG: print('Terminating thread #{id}'.format(id=self.index))
        self.stop = True        

def http_request(url, headers):
    """Simple HTTP request function with custom headers."""

    # Prepare TCP connection for HTTP
    connection = httplib.HTTPConnection(urlparse(url).hostname)

    # Send GET request with custom headers to the HTTP server
    connection.request(method='GET', url=url, body='', headers=headers)

    # Get response from the HTTP server
    response = connection.getresponse()

    # Cleanup response and retrieve HTML source code
    source = response.read().decode('utf-8')

    # Close connection
    connection.close()

    # Return size of response and HTML source code
    return (len(source), source)

def fuzz_user_agent(url, wordlist_path, threads_count):
    """User agent fuzzing."""

    # Default headers
    headers = {'User-Agent': STANDARD_UA, 'Accept': 'text/plain'}

    # Get standard response from the server (default User Agent)
    standard_size, standard_source = http_request(url, headers)

    # Remove reflected User Agent from source code
    standard_source = re.sub(re.compile('.*' + re.escape(headers['User-Agent']) + '.*\n'), '', standard_source, count=1)
    standard_size = standard_size - len(headers['User-Agent'].strip())

    # Init wordlist
    wordlist = Wordlist(wordlist_path)

    # Prepare threads
    threads = []

    # Create n threads based on threads_count number
    for index in range(1, threads_count + 1):
        # Instantiate a new User Agent fuzzer (copy.deepcopy prevents COW mechanism)
        worker = UAFuzz(index, wordlist, url, copy.deepcopy(headers), standard_size, standard_source)

        # Create thread based on new UAFuzz instance
        worker_thread = threading.Thread(target=worker.run)

        # Daemonize thread (not used here since we're not using Queues)
        worker_thread.daemon = True

        # Start the thread
        worker_thread.start()

        # Add thread to threads list
        threads += [{'thread': worker_thread, 'worker': worker}]

    try:
        # Wait for threads to finish
        for thread in threads:
            thread['thread'].join()
    except KeyboardInterrupt:
        # Close threads
        for thread in threads:
            thread['worker'].terminate()
            thread['thread'].join()

        # Close wordlist file descriptor
        wordlist.close()

        # Exit program
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
                        default=1,
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

        # Overwrite DEBUG with user value (bool)
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
