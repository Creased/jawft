# JAWFT - Just another web fuzzing tool

## A simple web fuzzing tool!

This project is an open-source fuzzer that can be used to improve your penetration testing on WEB application.

Feel free to improve it or use it in your own projects.

Each file is distributed "as is" in the hope that it will be useful, but without any warranty expressed or implied.

## Installation

This project has been developed using native Python libraries and is meant to be compatible both with Python 2 and 3.

## Usage

```raw
usage: fuzz.py [-h] [-w WORDLIST] -u URL [-t THREADS] [-d]

JAWFT - Just another web fuzzing tool v0.1-dev

optional arguments:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        path to wordlist
  -u URL, --url URL     URL to website
  -t THREADS, --threads THREADS
                        threads
  -d, --debug           Debug
```

Example (works both with Python 2 and 3!):

```bash
python3 fuzz.py -u http://192.168.56.101/ -w wordlist.txt -t 4 -d
```

## Features

 - User-Agent fuzzing:
   - Check change on the HTTP response (size and content)

## TODO

 - Improve change verification process
