#!/usr/bin/env python3
"""Derive Rapport stream keys and encrypt/decrypt the ChaCha20-Poly1305 AEAD layer.

Confirmed recipe for the Rapport pairing stream "main" (CUPairingStream):
- Per-direction 32-byte keys via HKDF-SHA512 over the final Pair-Verify secret,
  empty salt, info labels "ClientEncrypt-main" and "ServerEncrypt-main".
- ChaCha20-Poly1305 with a 16-byte Poly1305 tag.
- Independent 96-bit nonce per direction, starting at zero, incremented
  little-endian by one per record.
- The 4-byte Rapport frame header (0x08 || length_be24) is fed as AEAD AAD.

The peer advertised _cf=512, so the AES-GCM bit (0x20000000) was not set and the
cipher stays ChaCha20-Poly1305. The "hipri" stream is assumed analogous with
labels ClientEncrypt-hipri / ServerEncrypt-hipri (unverified, see notes).
"""

import argparse
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


KEY_LENGTH = 32
NONCE_LENGTH = 12
TAG_LENGTH = 16
CLIENT_LABEL = "ClientEncrypt-{stream}"
SERVER_LABEL = "ServerEncrypt-{stream}"


def decode_hex(value, expected_length=None):
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"invalid hexadecimal input: {error}") from error
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"expected {expected_length} bytes, got {len(decoded)}")
    return decoded


def derive_stream_key(secret, label):
    # CUPairingSession deriveKey wraps PairingSessionDeriveKey: HKDF-SHA512 with
    # an empty salt over the Pair-Verify shared secret, producing 32 bytes.
    kdf = HKDF(
        algorithm=hashes.SHA512(),
        length=KEY_LENGTH,
        salt=b"",
        info=label.encode("ascii"),
    )
    return kdf.derive(secret)


def derive_stream_keys(secret, stream="main"):
    return {
        "client": derive_stream_key(secret, CLIENT_LABEL.format(stream=stream)),
        "server": derive_stream_key(secret, SERVER_LABEL.format(stream=stream)),
    }


def nonce_for_counter(counter):
    if not 0 <= counter < (1 << (8 * NONCE_LENGTH)):
        raise ValueError("counter does not fit in a 96-bit nonce")
    return counter.to_bytes(NONCE_LENGTH, "little")


def encrypt_record(key, counter, plaintext, aad=b""):
    cipher = ChaCha20Poly1305(key)
    return cipher.encrypt(nonce_for_counter(counter), plaintext, aad or None)


def decrypt_record(key, counter, ciphertext, aad=b""):
    if len(ciphertext) < TAG_LENGTH:
        raise ValueError("ciphertext shorter than the 16-byte Poly1305 tag")
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce_for_counter(counter), ciphertext, aad or None)


def frame_aad(ciphertext_length):
    # Rapport TCP frame header: 0x08 || length_be24, used verbatim as AEAD AAD.
    if not 0 <= ciphertext_length < (1 << 24):
        raise ValueError("frame length does not fit in 24 bits")
    return b"\x08" + ciphertext_length.to_bytes(3, "big")


def self_test():
    secret = bytes.fromhex(
        "b813e0a3d9f4f1a2c5e6072839405162738495a6b7c8d9eafb0c1d2e3f405162"
    )
    keys = derive_stream_keys(secret, "main")
    if keys["client"] == keys["server"]:
        raise RuntimeError("client and server keys must differ by label")
    if any(len(value) != KEY_LENGTH for value in keys.values()):
        raise RuntimeError("HKDF-SHA512 did not produce 32-byte keys")

    # Nonce counter increments little-endian per record.
    if nonce_for_counter(0) != bytes(NONCE_LENGTH):
        raise RuntimeError("initial nonce must be all zero")
    if nonce_for_counter(1) != b"\x01" + bytes(NONCE_LENGTH - 1):
        raise RuntimeError("nonce must increment little-endian")

    # Round-trip a few records with the frame header as AAD.
    key = keys["client"]
    messages = [b"", b"main-stream-record", bytes(range(64))]
    for counter, plaintext in enumerate(messages):
        ciphertext = encrypt_record(key, counter, plaintext, frame_aad(0))
        if len(ciphertext) != len(plaintext) + TAG_LENGTH:
            raise RuntimeError("ciphertext must append a 16-byte tag")
        aad = frame_aad(len(ciphertext))
        ciphertext = encrypt_record(key, counter, plaintext, aad)
        recovered = decrypt_record(key, counter, ciphertext, aad)
        if recovered != plaintext:
            raise RuntimeError("AEAD round-trip mismatch")

    # AAD must be authenticated: a mismatching length is rejected.
    ciphertext = encrypt_record(key, 0, b"payload", frame_aad(7 + TAG_LENGTH))
    try:
        decrypt_record(key, 0, ciphertext, frame_aad(999))
    except Exception:
        pass
    else:
        raise RuntimeError("AAD mismatch should fail authentication")

    # A wrong nonce (counter) must also fail authentication.
    ciphertext = encrypt_record(key, 5, b"payload", b"")
    try:
        decrypt_record(key, 6, ciphertext, b"")
    except Exception:
        pass
    else:
        raise RuntimeError("nonce mismatch should fail authentication")

    print("Rapport HKDF-SHA512 key derivation and ChaCha20-Poly1305 self-tests passed")


def resolve_key(args):
    if args.key:
        return decode_hex(args.key, KEY_LENGTH)
    secret = decode_hex(args.secret)
    keys = derive_stream_keys(secret, args.stream)
    return keys["server"] if args.direction == "server" else keys["client"]


def add_key_arguments(parser):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--key", help="32-byte stream key as hex")
    group.add_argument("--secret", help="Pair-Verify shared secret as hex")
    parser.add_argument("--stream", default="main", help="stream name (default: main)")
    parser.add_argument(
        "--direction",
        choices=("client", "server"),
        default="client",
        help="which per-direction key to derive from --secret (default: client)",
    )
    parser.add_argument("--counter", type=int, default=0, help="record counter (nonce)")
    aad = parser.add_mutually_exclusive_group()
    aad.add_argument("--aad", help="explicit AEAD AAD as hex")
    aad.add_argument(
        "--frame-aad",
        action="store_true",
        help="derive AAD from the Rapport frame header for the given ciphertext length",
    )


def resolve_aad(args, ciphertext_length):
    if args.aad:
        return decode_hex(args.aad)
    if args.frame_aad:
        return frame_aad(ciphertext_length)
    return b""


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")

    derive_parser = subparsers.add_parser("derive")
    derive_parser.add_argument("secret", help="Pair-Verify shared secret as hex")
    derive_parser.add_argument("--stream", default="main", help="stream name")

    encrypt_parser = subparsers.add_parser("encrypt")
    add_key_arguments(encrypt_parser)
    encrypt_parser.add_argument("plaintext", help="plaintext record as hex")

    decrypt_parser = subparsers.add_parser("decrypt")
    add_key_arguments(decrypt_parser)
    decrypt_parser.add_argument("ciphertext", help="ciphertext record (with tag) as hex")

    args = parser.parse_args()

    if args.command == "self-test":
        self_test()
        return

    if args.command == "derive":
        secret = decode_hex(args.secret)
        for name, value in derive_stream_keys(secret, args.stream).items():
            print(f"{name}={value.hex()}")
        return

    key = resolve_key(args)
    if args.command == "encrypt":
        plaintext = decode_hex(args.plaintext)
        aad = resolve_aad(args, len(plaintext) + TAG_LENGTH)
        print(encrypt_record(key, args.counter, plaintext, aad).hex())
        return

    ciphertext = decode_hex(args.ciphertext)
    aad = resolve_aad(args, len(ciphertext))
    print(decrypt_record(key, args.counter, ciphertext, aad).hex())


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
