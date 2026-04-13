import idautils
import struct

KEY = [
    0xE2626DE7,
    0x22277C74,
    0xFF6C3CF0,
    0xB1AAC7AB,
]

DELTA = 0x481EAE9D
START_SUM = 1025483080

DECRYPT_FN = 0x3679EF450


def read_varint(buf, offset=0):
    value = buf[offset] & 0x7F
    shift = 7
    offset += 1

    if buf[offset - 1] & 0x80:
        while True:
            b = buf[offset]
            offset += 1
            value |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                break

    return value, offset


def decrypt_block(v9, v10):
    v11 = START_SUM

    while v11 != 0:
        v12 = (v11 + KEY[(v11 >> 11) & 3]) & 0xFFFFFFFF
        v11 = (v11 + DELTA) & 0xFFFFFFFF

        v10 = (v10 - (v12 ^ (v9 + ((v9 >> 4) ^ (v9 << 5))))) & 0xFFFFFFFF
        v9  = (v9  - ((v11 + KEY[v11 & 3]) ^ (v10 + ((v10 >> 4) ^ (v10 << 5))))) & 0xFFFFFFFF

    return v9, v10


def decrypt_buffer(data: bytes) -> bytes:
    buf = bytearray(data)
    
    if buf[0] == 0:
        i = 0
        while i < len(buf) and buf[i] == 0:
            i += 1
        return bytes(buf[i:])

    bit_len, payload_offset = read_varint(buf)

    decrypted = bytearray()

    for i in range(0, bit_len, 8):
        block = buf[payload_offset + i:payload_offset + i + 8]
        if len(block) < 8:
            break

        v9, v10 = struct.unpack("<II", block)
        v9, v10 = decrypt_block(v9, v10)
        decrypted += struct.pack("<II", v9, v10)

    return bytes(decrypted)


def main():
    for xref in idautils.XrefsTo(DECRYPT_FN):
        ea = xref.frm

        enc_ea = 0
        while ea != idc.BADADDR:
            if idc.print_insn_mnem(ea) == 'lea':
                if get_operand_type(ea, 0) == 0x1 and get_operand_value(ea, 0) == 0x1:
                    if get_operand_type(ea, 1) == 0x2:
                        enc_ea = idc.get_operand_value(ea, 1) & 0xFFFFFFFFFFFFFFFF
                    
                    break
            
            ea = idc.prev_head(ea)
        
        enc = get_bytes(enc_ea, 0x100)
        # print(hex(xref.frm), hex(enc_ea), enc)
        dec = decrypt_buffer(enc)
        # print(dec)
        print(f'[+] {dec.split(b'\x00')[0]} used at {hex(xref.frm)}')


if __name__ == '__main__':
    main()
