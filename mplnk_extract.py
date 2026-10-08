#!/usr/bin/env python3

from pathlib import Path

import argparse
import base64
import sys
import pylnk3
import re

ARG_MARKER = '-WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand '
SSP_MARKER = '[System.Text.Encoding]::UTF8.GetString([byte[]]('


def extract_urls(text):
    pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+|www\.[^\s<>"\'{}|\\^`\[\]]+'
    urls = re.findall(pattern, text, re.IGNORECASE)
    urls = [url.rstrip('.,;:!?)]}') for url in urls]
    return list(dict.fromkeys(urls))


def pl(lnk_path, offset, size, key):
    with open(lnk_path, 'rb') as lnk_file:
        lnk_file.seek(offset)
        data = bytearray(lnk_file.read(size))
    
    for i in range(size):
        data[i] ^= key
    
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Extract attacker-controlled server address from malicious LNK file."
    )
    parser.add_argument("lnk_file", help="Path to the malicious LNK file")
    args = parser.parse_args()

    try:
        # Extract and decode embedded payload inside LNK file
        lnk = pylnk3.parse(args.lnk_file)
        base = lnk.arguments
        offset = base.find(ARG_MARKER) + len(ARG_MARKER)
        embedded_payload = base64.b64decode(base[offset:]).decode('utf-16-le')
        
        # Locate offset, size, and key of 2nd stage payload
        offset = embedded_payload.find(SSP_MARKER) + len(SSP_MARKER)
        decode_routine = embedded_payload[offset:]
        decode_routine = decode_routine[:decode_routine.find('));')]
        decode_list = decode_routine.split(' ')
        if decode_list[0] != 'pl' or len(decode_list) != 4:
            print('[-] Unknown decode routine pattern')
            sys.exit(1)
        
        # Statically decode 2nd stage payload
        decode_args = [int(elem) for elem in decode_list[1:]]
        ss_payload = pl(args.lnk_file, decode_args[0], decode_args[1], decode_args[2])
        
        # Extract embedded URLs
        url_list = extract_urls(ss_payload.decode())
        for url in url_list:
            print(f'[+] Found: {url}')
        
    except any as exc:
        print(f'[-] Error: {exc}')
        sys.exit(1)


if __name__ == "__main__":
    main()
