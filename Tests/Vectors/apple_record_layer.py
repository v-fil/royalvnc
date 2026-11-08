#!/usr/bin/env python3
"""Prints the expected values in Tests/RoyalVNCKitTests/AppleRecordLayerTests.swift.

An oracle for Apple's record layer (RFB 3.889 session encryption) written from its description
(remotex docs/apple-vnc-889.md, "The record layer"), not from RoyalVNCKit's code: AES from
OpenSSL through the `cryptography` package, MD5, SHA-1 and SHA-256 from hashlib. CBC chaining
across records is done here by hand, one OpenSSL call per record with the previous record's last
ciphertext block as its IV.

    python3 -m pip install cryptography
    python3 -I Tests/Vectors/apple_record_layer.py           # readable
    python3 -I Tests/Vectors/apple_record_layer.py --swift \
        > Tests/RoyalVNCKitTests/AppleRecordLayerVectors.swift

Not part of any SwiftPM target.
"""

import hashlib
import random
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
TRAILER = 20


def ecb_encrypt(key, block):
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def cbc_encrypt(key, iv, data):
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def filler_length(body_length):
    return -(2 + body_length + TRAILER) % BLOCK


class Direction:
    """One direction: the key, the chaining block and the next sequence number."""

    def __init__(self, key, iv):
        self.key = key
        self.chain = iv
        self.seq = 0

    def record(self, body, filler=None, body_length=None, seq=None):
        """One record on the wire. `filler`, `body_length` and `seq` override the rules."""
        if filler is None:
            filler = bytes(filler_length(len(body)))
        if body_length is None:
            body_length = len(body)
        if seq is None:
            seq = self.seq
        self.seq += 1

        covered = body_length.to_bytes(2, "big") + body + filler
        plaintext = covered + hashlib.sha1(seq.to_bytes(4, "big") + covered).digest()
        assert len(plaintext) % BLOCK == 0

        ciphertext = cbc_encrypt(self.key, self.chain, plaintext)
        self.chain = ciphertext[-BLOCK:]

        return len(ciphertext).to_bytes(2, "big") + ciphertext

    def message(self, message):
        """A whole message: full records of 65,498 bytes, then the rest."""
        largest = (0xFFFF // BLOCK) * BLOCK - 2 - TRAILER
        out = b""
        start = 0
        while True:
            out += self.record(message[start:start + largest])
            start += largest
            if start >= len(message):
                return out


SWIFT = "--swift" in sys.argv[1:]
values = []


def show(name, value):
    values.append((name, f'"{value.hex()}"'))
    if not SWIFT:
        print(f"{name} = {value.hex()}")


def note(text):
    if not SWIFT:
        print(text)


# The wrap key after a type-30 login: MD5 of the Diffie-Hellman shared secret.
shared_secret = bytes((i * 7 + 3) & 0xFF for i in range(512))
wrap_key = hashlib.md5(shared_secret).digest()

key = bytes(range(0x10, 0x20))
iv = bytes(range(0xA0, 0xB0))
generation = 1

rekey = generation.to_bytes(4, "big") + ecb_encrypt(wrap_key, key) + ecb_encrypt(wrap_key, iv)

note("# Rekey")
show("sharedSecretSHA256", hashlib.sha256(shared_secret).digest())
show("wrapKey", wrap_key)
show("key", key)
show("iv", iv)
show("rekey", rekey)

# Client to server: zero filler, sequence numbers from 0.
client = Direction(key, iv)
messages = [
    bytes.fromhex("03010000000007800438"),  # FramebufferUpdateRequest, 10 bytes
    bytes.fromhex("0401000000000061"),                      # KeyEvent, 8 bytes
    bytes(range(27)),                                       # 27 bytes: 15 bytes of filler
    b"",                                                    # empty: the smallest record
]

note("\n# Client to server, one record each")
for index, message in enumerate(messages):
    show(f"clientMessage{index}", message)
    show(f"clientRecord{index}", client.record(message))

# A message larger than one record, on fresh keys.
large = bytes(i % 251 for i in range(2 * 65498 + 5))
wire = Direction(key, iv).message(large)

lengths = []
at = 0
while at < len(wire):
    length = int.from_bytes(wire[at:at + 2], "big")
    lengths.append(length)
    at += 2 + length

note("\n# Client to server, 131,001 bytes (i % 251)")
values.append(("largeRecordLengths", str(lengths)))
note(f"largeRecordLengths = {lengths}")
show("largeWireSHA256", hashlib.sha256(wire).digest())

# Server to client: random filler (the server's is random), on fresh keys.
rng = random.Random(1103)
server = Direction(key, iv)
bodies = [bytes(range(12)), b"", bytes((i * 3) & 0xFF for i in range(100)), b"\x2a"]
stream = b""
for body in bodies:
    filler = bytes(rng.randrange(256) for _ in range(filler_length(len(body))))
    stream += server.record(body, filler=filler)

note("\n# Server to client, random filler; the bodies concatenate")
for index, body in enumerate(bodies):
    show(f"serverBody{index}", body)
show("serverStream", stream)

note("\n# Server to client, each one record after a good first record")
first = lambda: Direction(key, iv)

bad = first()
good = bad.record(b"first")
show("goodFirstRecord", good)
show("replayedSequence", bad.record(b"second", seq=0))

bad = first()
bad.record(b"first")
show("littleEndianSequence", bad.record(b"second", seq=0x01000000))

bad = first()
bad.record(b"first")
show("extraFillerBlock", bad.record(bytes(10), filler=bytes(16)))

bad = first()
bad.record(b"first")
show("bodyLongerThanRecord", bad.record(bytes(10), body_length=9000))


if SWIFT:
    print("// Printed by Tests/Vectors/apple_record_layer.py --swift.")
    print("enum AppleRecordLayerVectors {")
    for name, value in values:
        print(f"\tstatic let {name} = {value}")
    print("}")
