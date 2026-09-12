#!/usr/bin/env python3
"""Reproduce the Rapport Pair-Verify crypto (plan A), offline and verifiable.

Reconstructed from CUPairingSession / RPConnection / CUPairingIdentity. This
helper implements the primitives and message assembly so a Linux receiver can
drive Pair-Verify; it does not open sockets.

Confirmed recipe:
- Ephemeral X25519 private key is HKDF-SHA512 derived, not raw random:
  ephemeralPrivate = HKDF-SHA512(IKM=random32, salt="Pair-Verify-ECDH-Salt",
                                 info="Pair-Verify-ECDH-Info", L=32)
  (clamping is applied by X25519 itself.)
- Shared secret = X25519(ephemeralPrivate, peerPublic); reject all-zero.
- Pair-Verify encryption key = HKDF-SHA512(IKM=sharedSecret,
      salt="Pair-Verify-Encrypt-Salt", info="Pair-Verify-Encrypt-Info", L=32).
- Sub-TLV AEAD: ChaCha20-Poly1305, no AAD, 16-byte tag; nonce = 4 zero bytes
  followed by the 8-byte ASCII label ("PV-Msg02"/"PV-Msg03"/"PV-Msg04").
- Identity signature: Ed25519 over (selfPK || identifier || peerPK).
- The final stream secret is the raw 32-byte X25519 shared secret (fed to the
  ClientEncrypt-main / ServerEncrypt-main HKDF in rapport-aead.py).

Framing is HomeKit-style TLV8: 1-byte type, 1-byte length, values >255 bytes
split into repeated same-type fragments.
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ECDH_SALT = b"Pair-Verify-ECDH-Salt"
ECDH_INFO = b"Pair-Verify-ECDH-Info"
ENCRYPT_SALT = b"Pair-Verify-Encrypt-Salt"
ENCRYPT_INFO = b"Pair-Verify-Encrypt-Info"

# TLV8 types
TLV_METHOD = 0
TLV_IDENTIFIER = 1
TLV_PUBLIC_KEY = 3
TLV_ENCRYPTED_DATA = 5
TLV_STATE = 6
TLV_ERROR = 7
TLV_SIGNATURE = 10
TLV_FLAGS = 25
TLV_APP_INFO = 29


def hkdf_sha512(ikm, salt, info, length=32):
    return HKDF(algorithm=hashes.SHA512(), length=length, salt=salt, info=info).derive(ikm)


def derive_ephemeral_private(random32):
    # Rapport derives the X25519 private scalar from random bytes via HKDF.
    if len(random32) != 32:
        raise ValueError("seed must be 32 bytes")
    scalar = hkdf_sha512(random32, ECDH_SALT, ECDH_INFO, 32)
    return X25519PrivateKey.from_private_bytes(scalar)


def x25519_shared(private_key, peer_public_bytes):
    peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
    secret = private_key.exchange(peer)
    if secret == bytes(len(secret)):
        raise ValueError("all-zero shared secret rejected")
    return secret


def pair_verify_encrypt_key(shared_secret):
    return hkdf_sha512(shared_secret, ENCRYPT_SALT, ENCRYPT_INFO, 32)


def msg_nonce(label):
    # 64-bit-counter ChaCha init with an 8-byte label == IETF nonce 0x00000000||label.
    if len(label) != 8:
        raise ValueError("Pair-Verify nonce label must be 8 bytes")
    return b"\x00\x00\x00\x00" + label


def aead_seal(key, label, plaintext):
    return ChaCha20Poly1305(key).encrypt(msg_nonce(label), plaintext, None)


def aead_open(key, label, ciphertext):
    return ChaCha20Poly1305(key).decrypt(msg_nonce(label), ciphertext, None)


def sign_identity(ed_private_bytes, self_pk, identifier, peer_pk):
    key = Ed25519PrivateKey.from_private_bytes(ed_private_bytes)
    return key.sign(self_pk + identifier + peer_pk)


def verify_identity(ed_public_bytes, signature, self_pk, identifier, peer_pk):
    Ed25519PublicKey.from_public_bytes(ed_public_bytes).verify(
        signature, self_pk + identifier + peer_pk
    )


def tlv8_encode(entries):
    # entries: list of (type, value_bytes); values >255 split into repeated fragments.
    out = bytearray()
    for tlv_type, value in entries:
        if not 0 <= tlv_type <= 255:
            raise ValueError("TLV type out of range")
        offset = 0
        # Emit at least one (possibly empty) fragment.
        while True:
            chunk = value[offset:offset + 255]
            out.append(tlv_type)
            out.append(len(chunk))
            out.extend(chunk)
            offset += len(chunk)
            if offset >= len(value):
                break
    return bytes(out)


def tlv8_decode(data):
    # Returns dict type -> coalesced value, concatenating repeated fragments.
    result = {}
    i = 0
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("truncated TLV8 header")
        tlv_type = data[i]
        length = data[i + 1]
        i += 2
        if i + length > len(data):
            raise ValueError("truncated TLV8 value")
        result[tlv_type] = result.get(tlv_type, b"") + data[i:i + length]
        i += length
    return result


def self_test():
    # TLV8 round-trip including >255-byte fragmentation.
    big = bytes(range(256)) + b"tail"
    encoded = tlv8_encode([(TLV_STATE, b"\x01"), (TLV_PUBLIC_KEY, big)])
    decoded = tlv8_decode(encoded)
    if decoded[TLV_STATE] != b"\x01" or decoded[TLV_PUBLIC_KEY] != big:
        raise RuntimeError("TLV8 round-trip failed")
    # The 256-byte value must have been split into 255 + 5.
    if encoded.count(bytes([TLV_PUBLIC_KEY, 255])) != 1:
        raise RuntimeError("TLV8 fragmentation missing")

    # Full Pair-Verify key agreement between a simulated client and server.
    client_priv = derive_ephemeral_private(os.urandom(32))
    server_priv = derive_ephemeral_private(os.urandom(32))
    client_pk = client_priv.public_key().public_bytes_raw()
    server_pk = server_priv.public_key().public_bytes_raw()

    client_shared = x25519_shared(client_priv, server_pk)
    server_shared = x25519_shared(server_priv, client_pk)
    if client_shared != server_shared:
        raise RuntimeError("X25519 shared secret mismatch")

    key = pair_verify_encrypt_key(client_shared)
    if pair_verify_encrypt_key(server_shared) != key:
        raise RuntimeError("Pair-Verify encryption key mismatch")

    # M2: server signs server_pk||id||client_pk, seals under PV-Msg02.
    server_id = b"AA:BB:CC:DD:EE:FF"
    server_ed = Ed25519PrivateKey.generate()
    server_ed_priv = server_ed.private_bytes_raw()
    server_ed_pub = server_ed.public_key().public_bytes_raw()
    sig = sign_identity(server_ed_priv, server_pk, server_id, client_pk)
    inner = tlv8_encode([(TLV_IDENTIFIER, server_id), (TLV_SIGNATURE, sig)])
    sealed = aead_seal(key, b"PV-Msg02", inner)

    # Client opens M2 and verifies the server signature.
    opened = tlv8_decode(aead_open(key, b"PV-Msg02", sealed))
    verify_identity(
        server_ed_pub, opened[TLV_SIGNATURE], server_pk, opened[TLV_IDENTIFIER], client_pk
    )

    # Tamper detection: a flipped signature byte must fail verification.
    bad = bytearray(opened[TLV_SIGNATURE])
    bad[0] ^= 1
    try:
        verify_identity(server_ed_pub, bytes(bad), server_pk, server_id, client_pk)
    except Exception:
        pass
    else:
        raise RuntimeError("tampered signature must fail")

    # Wrong nonce label must fail AEAD.
    try:
        aead_open(key, b"PV-Msg03", sealed)
    except Exception:
        pass
    else:
        raise RuntimeError("wrong nonce label must fail AEAD")

    print("Pair-Verify TLV8, X25519, HKDF-SHA512, ChaCha20-Poly1305, Ed25519 self-tests passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")

    ecdh = subparsers.add_parser("ecdh")
    ecdh.add_argument("seed", help="32-byte random seed as hex")
    ecdh.add_argument("peer_public", help="peer X25519 public key as hex")

    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return

    priv = derive_ephemeral_private(bytes.fromhex(args.seed))
    shared = x25519_shared(priv, bytes.fromhex(args.peer_public))
    print(f"public={priv.public_key().public_bytes_raw().hex()}")
    print(f"shared={shared.hex()}")
    print(f"pv_encrypt_key={pair_verify_encrypt_key(shared).hex()}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
