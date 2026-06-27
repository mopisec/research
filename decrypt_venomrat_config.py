#!/usr/bin/env python3

import base64
import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# From ITW sample (MD5: fe2427e532f6d9a6c4e2dfd9c1903187)
KEY_B64 = "WTY4WEdPa0pEQnE0eXBMZ1JnVjg1NjlkUUNSZFdIamc="
ENC = {
    'Por_ts': "16wgTcFzwAnc9Zil2o8IbFPEN1Jc9PrxFvKc11tiy48NJUHjEc3c13TRTt/aa98X2AQbVBVc3mTH7DQ1CdPsbw==", 
	'Hos_ts': "gXAkptdZO7mD2uMaqtZ25YVkwZuFQNWri5hO5FkXI9YrVoVmhs9PD+/83t/1TC0BxebTtm8ZCRC0ond3V5tC5Q==", 
	'Ver_sion': "WJUFuF3dOPQMl2ujeWEbgWYeR80KyXA+Wc1xg5+9iwd/xsYaYfngWtsbnKw7vdPeZboIDYq6vjpCsNXBbWp7YvalxTjFy0UySfE2rQ/f9rNsLx26+8AA3HtyQC2oI5Qx", 
	'In_stall': "dYOrjo7AnoI32cYV/WqAhxq9KqKXaDPs6BIY0BHPX5tI+oBAN4sx5hwQMcCP27PuNk4UXZ0p9g/dLz23qtkyuQ==", 
	'MTX': "mt+0lXYz8eE+hxYz8J3uumXzK4+TTMKg5nElzyZA4qjyg6r5BZVkP+98WfZV1e0GSlkihobYPLv9Gdr2c2MaEw==", 
	'Paste_bin': "9SmeNkFhSVgbRxsLA75HIiIrDC8PQwyWkBy2VxSmjPQYXXv3hxOH0tZQJZJOML+XDmGnD1DB1ub0lRby7vk8eQ==", 
	'BS_OD': "hP526Q5amH+c1fYkD/P1OeBmtHAI1gNZkB7mY3BX899N2A5K9Y3pS2VcwtLSAPf2Xbdnp4MQYp0GjeSpqx+mNw==", 
	'Group': "5RhfmLLfeq6/S9Bj5DpzE1D5k1AAbyWMMusK3kRIbbvustviBn2XCUkQraMzjorSEtc2iQbp8Kk+uN4ZbZHoRA==", 
	'Anti_Process': "Mqf0LDQ9dQBwb6W3z6wYLb+OUcWiS6jmXBoo8/pwj6OErzcCCNn08Bv4a9swmIjDDSyyzkTMWL2XZ+YUsIEnxg==", 
	'An_ti': "EumeMRkL4Di9f8jBtnsBj/pR4R2VP2+QPx6M9EoqawXkdDHe4NESpEgCtJeKSqGYPFFiWgpYCoAzUOPBLRJGDg=="
}

SALT = b"VenomRATByVenom"
ITERATIONS = 50000


def derive_keys(master_key: str):
    dk = hashlib.pbkdf2_hmac(
        "sha1",
        master_key.encode(),
        SALT,
        ITERATIONS,
        dklen=96,
    )

    aes_key = dk[:32]
    auth_key = dk[32:]

    return aes_key, auth_key


def decrypt(enc_b64: str, aes_key: bytes, auth_key: bytes):
    blob = base64.b64decode(enc_b64)

    mac = blob[:32]
    iv = blob[32:48]
    ciphertext = blob[48:]

    calc = hmac.new(auth_key, blob[32:], hashlib.sha256).digest()

    if not hmac.compare_digest(mac, calc):
        raise ValueError("HMAC verification failed")

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode("utf-8")


def main():
    master_key = base64.b64decode(KEY_B64).decode()

    print("[+] Master key :", master_key)

    aes_key, auth_key = derive_keys(master_key)

    for entry in ENC:
        dec = decrypt(ENC[entry], aes_key, auth_key)

        print(f"[+] {entry}:")
        print(dec)


if __name__ == "__main__":
    main()
