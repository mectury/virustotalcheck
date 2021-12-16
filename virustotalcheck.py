#!/usr/bin/python
# Docs: https://www.virustotal.com/en/documentation/public-api/

import os, hashlib, sys
import requests
from time import sleep


hasher = hashlib.sha256()   # sha256 is used by vt
BLOCKSIZE = 65536           # Buffer size for sha256 calculating
vt_api_key = '4e3202fdbe953d628f650229af5b3eb49cd46b2d3bfe5546ae3c5fa48b554e0c'  # SysInternals


REQUESTS_PER_MINUTE = 4 # public rate
API_DELAY_TIME_SEC = 60 / REQUESTS_PER_MINUTE


def calculate_sha256(file_path):
    with open(file_path, 'rb') as cur_file:
        buf = cur_file.read(BLOCKSIZE)

        while len(buf) > 0:
            hasher.update(buf)
            buf = cur_file.read(BLOCKSIZE)

    return hasher.hexdigest()


def calculate_argv_files_hash():
    hash_table = {} # key - hash, value - filename

    for file in sys.argv[1:]:
        if not os.path.isfile(file):
            print(f"\t!!! File is not found: {file}")
            continue

        hash = calculate_sha256(file)
        hash_table[hash] = file

    return hash_table


def make_session(use_tor_proxy=True):
    session = requests.session()
    if(use_tor_proxy):
        session.proxies['http'] = 'socks5h://localhost:9050'
        session.proxies['https'] = 'socks5h://localhost:9050'
    return session

hash_table = calculate_argv_files_hash()


session = make_session()
for hash_n, filename in hash_table.items():
    res = session.request("GET", url=f"https://virustotal.com/vtapi/v2/file/report?apikey={vt_api_key}&resource={hash_n}")
    STATUS_OK = 200

    # Отладочка :з
    # if res.status_code != STATUS_OK:
    #    print("SHIT HAPPENED")
    #    print(res.status_code)
    #    exit(0)
   
    if res.status_code == STATUS_OK:
        data = res.json()
        was_checked = data["response_code"] == 1
        if was_checked:
            print(f"{filename} hash is FOUND in VirusTotal dbs")

    sleep(API_DELAY_TIME_SEC)

   

session.close()