from gzip import GzipFile
from io import BytesIO

import hashlib
import struct
import sys


def read_data_block(data, offset):
    block_size = struct.unpack('<I', data[offset:offset+4])[0]
    if block_size > 0:
        try:
            block = data[offset+4:offset+4+block_size]
            return block
        except IndexError:
            print(f'[-] Failed to read data block (offset = {hex(offset)}, block_size = {hex(block_size)})')
            exit(1)
    else:
        None


def main():
    if len(sys.argv) != 2:
        print(f'[-] Usage: python3 {sys.argv[0]} [PIVOTPIPE_LOADER_BIN]')
        exit(1)
    
    with open(sys.argv[1], 'rb') as pp_file:
        pp = pp_file.read()
    
    try:
        blob_offset = pp.index(b'NBPK1')
    except ValueError:
        print(f'[-] Error: Magic "NBPK1" was not found. Is this really PIVOTPIPE loader?')
        exit(1)
    finally:
        print(f'[!] Blob Offset = {hex(blob_offset)}')
        
    # Magic
    blob_offset += 5
    
    # XOR Key
    xor_key = read_data_block(pp, blob_offset)
    blob_offset += 4 + len(xor_key)
    print(f'[!] XOR Key = {xor_key}')
    
    # Config
    config = read_data_block(pp, blob_offset)
    blob_offset += 4 + len(config)
    print(f'[!] Config = {config.decode()}')
    
    # Public Key
    public_key = read_data_block(pp, blob_offset)
    blob_offset += 4 + len(public_key)
    print(f'[!] Public Key = {public_key.hex()}')
    
    # RAT
    payload = bytearray(read_data_block(pp, blob_offset))
    blob_offset += 4 + len(payload)
    
    # RAT (XOR Decode)
    for i in range(len(payload)):
        payload[i] ^= xor_key[i % len(xor_key)]
    
    # RAT (GZIP Decompress)
    io = BytesIO()
    io.write(payload)
    io.seek(0)
    with GzipFile(fileobj=io, mode='rb') as gzip_file:
        dec_payload = gzip_file.read()
    
    # RAT (Output)
    print(f'[!] SHA256(Payload) = {hashlib.sha256(dec_payload).hexdigest()}')
    with open(f'{sys.argv[1]}.payload', 'wb') as payload_file:
        payload_file.write(dec_payload)
    
    print(f'[+] Saved RAT Payload as {sys.argv[1]}.payload')
    
    # Sleep Mask COFF (Optional)
    coff = read_data_block(pp, blob_offset)
    if coff is not None:
        print(f'[!] SHA256(COFF) = {hashlib.sha256(coff).hexdigest()}')
        with open(f'{sys.argv[1]}.sleepmask', 'wb') as coff_file:
            coff_file.write(coff)
        
        print(f'[+] Saved Sleep Mask COFF as {sys.argv[1]}.sleepmask')
    

if __name__ == '__main__':
    main()
