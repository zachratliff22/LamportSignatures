#!/usr/bin/python3

# Author: Zachary Ratliff
# Simple Python implementation of Lamport signature scheme

import hashlib
import math
import secrets
import sys

CHAR_ENC = 'utf-8'
BYTE_ORDER = sys.byteorder
SK = 0
PK = 1

# Generate a keypair for a one-time signature
def keygen():
    sk = [[0 for x in range(256)] for y in range(2)]
    pk = [[0 for x in range(256)] for y in range(2)] 
    for i in range(0,256):
        #secret key
        sk[0][i] = secrets.token_bytes(32)
        sk[1][i] = secrets.token_bytes(32)
        #public key
        pk[0][i] = hashlib.sha256(sk[0][i]).digest()
        pk[1][i] = hashlib.sha256(sk[1][i]).digest()

    keypair = [sk,pk]
    return keypair

# Sign messages using Lamport one-time signatures
def sign(m, sk):
    sig = [0 for x in range(256)]
    h = int.from_bytes(hashlib.sha256(m.encode(CHAR_ENC)).digest(), BYTE_ORDER)
    for i in range(0,256):
        b = h >> i & 1
        sig[i] = sk[b][i]

    return sig

# Verify Lamport message signatures
def verify(m, sig, pk):
    h = int.from_bytes(hashlib.sha256(m.encode(CHAR_ENC)).digest(), BYTE_ORDER)
    for i in range(0,256):
        b = h >> i & 1
        check = hashlib.sha256(sig[i]).digest()
        if pk[b][i] != check:
            return False

    return True

keypair = keygen()
message = "Lamport signatures are cool!"
sig = sign(message, keypair[SK])
print(verify(message, sig, keypair[PK]))

