import os
import binascii


def generate_nonce(length=32):
    return int(binascii.hexlify(os.urandom(length)), 16)
