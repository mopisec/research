import struct

import idautils
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import idc


FUNC_NAME = "sub_3679EF450"
KEY_ADDR = 0x3679FC780
DELTA = 0x481EAE9D
INITIAL_SUM = 0x3D1FA148
MAX_BACKTRACK_INSNS = 8
MAX_CHAIN_RECORDS = 128


def u32(x):
    return x & 0xFFFFFFFF


def read_bytes(ea, size):
    data = ida_bytes.get_bytes(ea, size)
    if data is None or len(data) != size:
        raise ValueError("cannot read %d bytes at 0x%X" % (size, ea))
    return data


def read_varint(ea):
    first = ida_bytes.get_byte(ea)
    if first is None:
        raise ValueError("cannot read varint at 0x%X" % ea)

    value = first
    size = 1
    if value & 0x80:
        value &= 0x7F
        shift = 7
        while True:
            b = ida_bytes.get_byte(ea + size)
            if b is None:
                raise ValueError("truncated varint at 0x%X" % ea)
            size += 1
            value |= (b & 0x7F) << shift
            shift += 7
            if b < 0x80:
                break
    return value, size


def load_key():
    return struct.unpack("<4I", read_bytes(KEY_ADDR, 16))


def decrypt_block(v0, v1, key_words):
    total = INITIAL_SUM
    while total != 0:
        v1 = u32(v1 - (u32(total + key_words[(total >> 11) & 3]) ^ u32(v0 + ((v0 >> 4) ^ u32(v0 << 5)))))
        total = u32(total + DELTA)
        v0 = u32(v0 - (u32(total + key_words[total & 3]) ^ u32(v1 + ((v1 >> 4) ^ u32(v1 << 5)))))
    return v0, v1


def decrypt_record(ea, key_words):
    start = ea
    while ida_bytes.is_loaded(ea) and ida_bytes.get_byte(ea) == 0:
        ea += 1

    if not ida_bytes.is_loaded(ea):
        raise ValueError("record start 0x%X is not loaded" % ea)

    if ea != start:
        return {
            "start_ea": start,
            "record_ea": ea,
            "next_ea": ea,
            "plaintext": b"",
            "text": "",
            "is_separator": True,
        }

    plain_len, header_len = read_varint(ea)
    if plain_len <= 0 or (plain_len % 8) != 0:
        raise ValueError("invalid plaintext length %d at 0x%X" % (plain_len, ea))

    cipher_ea = ea + header_len
    cipher = read_bytes(cipher_ea, plain_len)
    out = bytearray()
    for off in range(0, plain_len, 8):
        v0, v1 = struct.unpack_from("<2I", cipher, off)
        p0, p1 = decrypt_block(v0, v1, key_words)
        out += struct.pack("<2I", p0, p1)

    text = out.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    return {
        "start_ea": start,
        "record_ea": ea,
        "next_ea": cipher_ea + plain_len,
        "plaintext": bytes(out),
        "text": text,
        "is_separator": False,
    }


def annotate_record(ea, text):
    idc.set_cmt(ea, "encstr: %s" % text, 0)


def is_probably_data_ea(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    return seg.perm & ida_segment.SEGPERM_EXEC == 0


def find_direct_call_targets(func_ea):
    targets = set()
    for call_ea in idautils.CodeRefsTo(func_ea, False):
        cur = call_ea
        for _ in range(MAX_BACKTRACK_INSNS):
            cur = idc.prev_head(cur)
            if cur == idc.BADADDR:
                break
            mnem = idc.print_insn_mnem(cur).lower()
            dst = idc.print_operand(cur, 0).lower()
            if dst != "rcx":
                continue
            if mnem not in ("lea", "mov"):
                break
            target = idc.get_operand_value(cur, 1)
            if target != idc.BADADDR and ida_bytes.is_loaded(target) and is_probably_data_ea(target):
                targets.add(target)
            break
    return sorted(targets)


def decode_chain(start_ea, key_words):
    results = []
    seen = set()
    cur = start_ea
    for _ in range(MAX_CHAIN_RECORDS):
        if cur in seen or not ida_bytes.is_loaded(cur):
            break
        seen.add(cur)
        try:
            item = decrypt_record(cur, key_words)
        except Exception:
            break
        results.append(item)
        nxt = item["next_ea"]
        if nxt <= cur:
            break
        cur = nxt
    return results


def main():
    func_ea = ida_name.get_name_ea(idc.BADADDR, FUNC_NAME)
    if func_ea == idc.BADADDR:
        raise RuntimeError("cannot resolve %s" % FUNC_NAME)

    key_words = load_key()
    start_eas = find_direct_call_targets(func_ea)
    if not start_eas:
        print("[!] no direct blob starts found")
        return

    print("[*] key = %s" % (" ".join("0x%08X" % x for x in key_words)))
    print("[*] found %d direct blob starts" % len(start_eas))

    total = 0
    visited_records = set()
    for start_ea in start_eas:
        chain = decode_chain(start_ea, key_words)
        if not chain:
            continue
        first_record = next((item["record_ea"] for item in chain if not item["is_separator"]), None)
        if first_record is None or first_record in visited_records:
            continue
        print("\n[+] chain start 0x%X" % start_ea)
        for item in chain:
            rec_ea = item["record_ea"]
            if item["is_separator"]:
                continue
            if rec_ea in visited_records:
                continue
            visited_records.add(rec_ea)
            annotate_record(rec_ea, item["text"])
            print("    0x%X -> %r" % (rec_ea, item["text"]))
            total += 1

    print("\n[*] annotated %d decrypted strings" % total)


if __name__ == "__main__":
    main()
