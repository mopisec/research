import idaapi
import idautils
import ida_funcs
import pefile
import struct

ENUM_NAME = 'APIHASH'

# Reference: https://gist.github.com/trietptm/5cd60ed6add5adad6a34098ce255949a
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


def calculate_hash(api_name):
    hash_value = 0
    for char in api_name:
        hash_value = char + ror(hash_value, 11, 32)
    
    return hash_value


def main():
    # Calculate hash value of API functions
    api_dict = {}
    for dll in ['kernel32.dll', 'ntdll.dll']:
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

    for hash_value in api_dict:
        enum_value = idc.get_enum_member(enum, hash_value, 0, 0)
        if enum_value == -1:
            idc.add_enum_member(enum, ENUM_NAME + "_" + api_dict[hash_value].decode(), hash_value)


if __name__ == '__main__':
    main()
