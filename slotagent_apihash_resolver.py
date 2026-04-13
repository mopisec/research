import ctypes
import idaapi
import idautils
import ida_funcs
import pefile
import struct

API_RESOLVER_FN = 0x3679EB650
ENUM_NAME = 'APIHASH'


def calculate_hash(string):
    hash_value = 5218
    string = string.lower()
    for char in string:
        hash_value = (char + ((33 * hash_value) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return hash_value


def main():
    # Calculate hash value of API functions
    api_dict = {}
    for dll in ['kernel32.dll', 'winhttp.dll', 'advapi32.dll', 'user32.dll', 'gdi32.dll', 'ws2_32.dll', 'iphlpapi.dll', 'bcrypt.dll', 'crypt32.dll', 'ntdll.dll']:
        try:
            pe = pefile.PE('C:\\Windows\\System32\\' + dll)
            api_list = [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
            api_list = [api for api in api_list if api != None]
        except (AttributeError, pefile.PEFormatError):
            continue

        for api in api_list:
            api_dict[calculate_hash(api)] = api

    # Create enum type for API hash
    enum = idc.get_enum(ENUM_NAME)
    if enum == idc.BADADDR:
        enum = idc.add_enum(idaapi.BADNODE, ENUM_NAME, idaapi.hex_flag())

    # Collect used API hash values
    for xref in idautils.XrefsTo(API_RESOLVER_FN):
        ea = xref.frm

        hash_value = 0
        while ea != idc.BADADDR:
            if idc.print_insn_mnem(ea) == 'mov':
                if get_operand_type(ea, 0) == 0x1 and get_operand_value(ea, 0) == 0x2:
                    if get_operand_type(ea, 1) == 0x5:
                        hash_value = idc.get_operand_value(ea, 1) & 0xFFFFFFFF
                    
                    break
            
            ea = idc.prev_head(ea)

        if hash_value == 0:
            print(f'[-] Skip at {hex(xref.frm)}')
            continue

        # Print API hashing resolution result
        if hash_value not in api_dict:
            print(f'[-] Failed: {hex(hash_value)} used at {hex(xref.frm)}')
            continue
        else:
            print(f'[+] Resolved: {hex(hash_value)} ---> {api_dict[hash_value]} used at {hex(xref.frm)}')

        # Add enum member and apply it
        enum_value = idc.get_enum_member(enum, hash_value, 0, 0)
        if enum_value == -1:
            idc.add_enum_member(enum, ENUM_NAME + "_" + api_dict[hash_value].decode(), hash_value)

        idc.op_enum(ea, 0, enum, 0)


if __name__ == '__main__':
    main()
