from Crypto.Util.number import *
from hashlib import sha256
from pwn import xor
record = [1, 3, 1, 0, 9029]

buffer = long_to_bytes(0, 8)

for i in record:
    buffer = xor(buffer, (long_to_bytes(i, 8)))

h = sha256(buffer).digest()

print([i for i in h])

from os import urandom

for _ in range(4):
    print("0x" + bytes.hex(urandom(8)) + "u64")
