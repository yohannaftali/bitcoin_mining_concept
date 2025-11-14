"""
Helper to build the 80-byte block header and compute double-SHA256 for a mining.notify JSON.

Usage (examples):
  python -m src.backend.notify_helper --notify-file notify.json --nonce 0x1
  cat notify.json | python -m src.backend.notify_helper --nonce 12345

The script attempts to mimic the header building used in the repository's
`stratum_miner.py` so you can compare the 80-byte header and resulting hash
against an ESP32 firmware (NerdMiner_v2) printout.
"""

import argparse
import sys
import json
from binascii import hexlify, unhexlify
import struct
import hashlib


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def calc_merkle_root(coinbase_hex: str, merkle_branches_hex: list) -> str:
    h = double_sha256(unhexlify(coinbase_hex))
    for br in (merkle_branches_hex or []):
        h = double_sha256(h + unhexlify(br))
    return hexlify(h[::-1]).decode()


def create_block_header(version: int, prev_hash_hex: str, merkle_root_hex: str, ntime: int, nbits: int, nonce: int) -> bytes:
    header = b''
    header += struct.pack('<I', version)
    header += unhexlify(prev_hash_hex)[::-1]
    header += unhexlify(merkle_root_hex)[::-1]
    header += struct.pack('<I', ntime)
    header += struct.pack('<I', nbits)
    header += struct.pack('<I', nonce)
    return header


def parse_notify(obj: dict):
    # Expected mining.notify params: [job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
    params = obj.get('params') or []
    if not params or len(params) < 8:
        raise ValueError('notify object missing required params')
    job_id = params[0]
    prevhash = params[1]
    coinb1 = params[2]
    coinb2 = params[3]
    merkle_branch = params[4] or []
    version = int(params[5], 16) if isinstance(params[5], str) else int(params[5])
    nbits = int(params[6], 16) if isinstance(params[6], str) else int(params[6])
    ntime = int(params[7], 16) if isinstance(params[7], str) else int(params[7])
    return {
        'job_id': job_id,
        'prevhash': prevhash,
        'coinb1': coinb1,
        'coinb2': coinb2,
        'merkle_branch': merkle_branch,
        'version': version,
        'nbits': nbits,
        'ntime': ntime,
    }


def build_coinbase(extranonce1: str, extranonce2: str, coinb1: str, coinb2: str) -> str:
    return coinb1 + extranonce1 + extranonce2 + coinb2


def main():
    p = argparse.ArgumentParser(description='Build 80-byte header and compute double-SHA256 for a mining.notify JSON')
    p.add_argument('--notify-file', help='Path to a JSON file containing a mining.notify object. If omitted, read from stdin')
    p.add_argument('--nonce', help='Nonce decimal or hex (e.g. 0x1). If omitted, header printed but hash not computed', default=None)
    p.add_argument('--extranonce2', help='Override extranonce2 hex (without 0x). If omitted the helper tries common defaults (0001, 00000001) based on extranonce2_size in notify/result).', default=None)
    p.add_argument('--extranonce1', help='Override extranonce1 hex (without 0x). If omitted, try to use params[1] of a mining.subscribe response if provided inline in the notify JSON under "extranonce1" key. Otherwise fail.', default=None)
    args = p.parse_args()

    # read JSON
    if args.notify_file:
        with open(args.notify_file, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    else:
        data = json.load(sys.stdin)

    # If user passed a top-level subscription result, accept that too
    if isinstance(data, dict) and data.get('method') == 'mining.notify':
        notify = parse_notify(data)
    elif isinstance(data, dict) and 'params' in data:
        # Maybe the user gave only the params array as an object
        notify = parse_notify(data)
    else:
        # Try to find a mining.notify inside a list or nested structure
        if isinstance(data, list):
            # find first element that looks like a mining.notify
            found = None
            for elt in data:
                if isinstance(elt, dict) and elt.get('method') == 'mining.notify':
                    found = elt
                    break
            if found is None:
                raise ValueError('Could not locate mining.notify in provided JSON list')
            notify = parse_notify(found)
        else:
            raise ValueError('Unsupported JSON input format for notify')

    # Determine extranonce1: try top-level field or provided override
    extranonce1 = args.extranonce1
    if not extranonce1:
        # some clients include extranonce1 in a adjacent subscribe result stored in the JSON under 'extranonce1'
        extranonce1 = data.get('extranonce1') if isinstance(data, dict) else None
    if not extranonce1:
        raise ValueError('extranonce1 not provided; please pass --extranonce1 or include it in the JSON as "extranonce1"')

    # determine extranonce2
    extranonce2 = args.extranonce2
    if not extranonce2:
        # fallback to size guesses
        # Look for extranonce2_size in the input JSON (some dumps include it)
        size_guess = None
        if isinstance(data, dict) and 'extranonce2_size' in data:
            try:
                size_guess = int(data.get('extranonce2_size'))
            except Exception:
                size_guess = None
        if size_guess is None:
            # default to 4 bytes => 8 hex chars
            size_guess = 4
        if size_guess == 2:
            extranonce2 = '0001'
        elif size_guess == 4:
            extranonce2 = '00000001'
        elif size_guess == 8:
            extranonce2 = '0000000000000001'
        else:
            extranonce2 = '{:0{width}x}'.format(1, width=size_guess * 2)

    coinbase_hex = build_coinbase(extranonce1, extranonce2, notify['coinb1'], notify['coinb2'])
    merkle_root_hex = calc_merkle_root(coinbase_hex, notify.get('merkle_branch'))

    header80 = create_block_header(notify['version'], notify['prevhash'], merkle_root_hex, notify['ntime'], notify['nbits'], 0)
    print('80-byte header (nonce=0):', hexlify(header80).decode())

    if args.nonce is not None:
        nraw = args.nonce
        if isinstance(nraw, str) and nraw.startswith(('0x', '0X')):
            nonce = int(nraw, 16)
        else:
            nonce = int(nraw, 0)
        header_nonce = create_block_header(notify['version'], notify['prevhash'], merkle_root_hex, notify['ntime'], notify['nbits'], nonce)
        h = double_sha256(header_nonce)
        print('Nonce used: 0x{:08x}'.format(nonce))
        print('Header (with nonce):', hexlify(header_nonce).decode())
        print('Double SHA256 (big-endian hex of digest):', hexlify(h[::-1]).decode())
        print('Double SHA256 (native digest hex):', hexlify(h).decode())
    else:
        print('No nonce provided; pass --nonce to compute double-sha256 for a nonce')


if __name__ == '__main__':
    main()
