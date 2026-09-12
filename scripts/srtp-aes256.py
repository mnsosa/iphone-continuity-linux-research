#!/usr/bin/env python3
"""Derive RFC 6188 keys and authenticate/decrypt AES-256-CM SRTP packets."""

import argparse
import hashlib
import hmac
import subprocess
import sys


AUTH_TAG_LENGTH = 10
MASTER_KEY_LENGTH = 32
MASTER_SALT_LENGTH = 14


def decode_hex(value, expected_length=None):
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"invalid hexadecimal input: {error}") from error
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError(f"expected {expected_length} bytes, got {len(decoded)}")
    return decoded


def openssl_cipher(cipher, key, iv, data):
    command = ["openssl", "enc", f"-{cipher}", "-K", key.hex(), "-nosalt"]
    if iv is None:
        command.append("-nopad")
    else:
        command.extend(("-iv", iv.hex()))
    try:
        result = subprocess.run(command, input=data, capture_output=True, check=True)
    except FileNotFoundError as error:
        raise RuntimeError("openssl is required") from error
    except subprocess.CalledProcessError as error:
        message = error.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"openssl failed: {message}") from error
    return result.stdout


def derive_key(master_key, master_salt, label, length):
    # RFC 3711 section 4.3.3: x = master_salt XOR (label || index DIV kdr),
    # followed by multiplication by 2^16. Continuity uses the initial kdr=0 keys.
    input_block = bytearray(master_salt + b"\x00\x00")
    input_block[7] ^= label
    base = int.from_bytes(input_block, "big")
    output = bytearray()
    for counter in range((length + 15) // 16):
        block = (base + counter).to_bytes(16, "big")
        output.extend(openssl_cipher("aes-256-ecb", master_key, None, block))
    return bytes(output[:length])


def derive_session_keys(master_material):
    master_key = master_material[:MASTER_KEY_LENGTH]
    master_salt = master_material[MASTER_KEY_LENGTH:]
    return {
        "encryption": derive_key(master_key, master_salt, 0x00, 32),
        "authentication": derive_key(master_key, master_salt, 0x01, 20),
        "salt": derive_key(master_key, master_salt, 0x02, 14),
    }


def rtp_header_length(packet):
    if len(packet) < 12 or packet[0] >> 6 != 2:
        raise ValueError("packet is not RTP version 2")
    length = 12 + 4 * (packet[0] & 0x0F)
    if len(packet) < length:
        raise ValueError("truncated RTP CSRC list")
    if packet[0] & 0x10:
        if len(packet) < length + 4:
            raise ValueError("truncated RTP extension header")
        extension_words = int.from_bytes(packet[length + 2:length + 4], "big")
        length += 4 + extension_words * 4
    if len(packet) < length + AUTH_TAG_LENGTH:
        raise ValueError("truncated SRTP packet")
    return length


def decrypt_rtp(master_material, packet, roc):
    header_length = rtp_header_length(packet)
    authenticated = packet[:-AUTH_TAG_LENGTH]
    supplied_tag = packet[-AUTH_TAG_LENGTH:]
    keys = derive_session_keys(master_material)
    expected_tag = hmac.new(
        keys["authentication"], authenticated + roc.to_bytes(4, "big"), hashlib.sha1
    ).digest()[:AUTH_TAG_LENGTH]
    if not hmac.compare_digest(supplied_tag, expected_tag):
        raise ValueError(
            f"authentication failed: supplied={supplied_tag.hex()} expected={expected_tag.hex()}"
        )

    sequence = int.from_bytes(packet[2:4], "big")
    ssrc = int.from_bytes(packet[8:12], "big")
    packet_index = (roc << 16) | sequence
    shifted_salt = int.from_bytes(keys["salt"] + b"\x00\x00", "big")
    iv = (shifted_salt ^ (ssrc << 64) ^ (packet_index << 16)).to_bytes(16, "big")
    plaintext = openssl_cipher(
        "aes-256-ctr", keys["encryption"], iv, authenticated[header_length:]
    )
    return authenticated[:header_length], plaintext


def self_test():
    material = decode_hex(
        "f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6"
        "3b04803de51ee7c96423ab5b78d2",
        MASTER_KEY_LENGTH + MASTER_SALT_LENGTH,
    )
    expected = {
        "encryption": "5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4",
        "authentication": "fd9c32d39ed5fbb5a9dc96b30818454d1313dc05",
        "salt": "fa31791685ca444a9e07c6c64e93",
    }
    actual = derive_session_keys(material)
    failures = [name for name, value in actual.items() if value.hex() != expected[name]]
    if failures:
        raise RuntimeError(f"RFC 6188 KDF self-test failed: {', '.join(failures)}")

    header = bytes.fromhex("806400010000032011223344")
    plaintext = b"Continuity Camera SRTP test"
    roc = 0
    packet_index = int.from_bytes(header[2:4], "big")
    ssrc = int.from_bytes(header[8:12], "big")
    shifted_salt = int.from_bytes(actual["salt"] + b"\x00\x00", "big")
    iv = (shifted_salt ^ (ssrc << 64) ^ (packet_index << 16)).to_bytes(16, "big")
    ciphertext = openssl_cipher("aes-256-ctr", actual["encryption"], iv, plaintext)
    authenticated = header + ciphertext
    tag = hmac.new(
        actual["authentication"], authenticated + roc.to_bytes(4, "big"), hashlib.sha1
    ).digest()[:AUTH_TAG_LENGTH]
    decoded_header, decoded_payload = decrypt_rtp(material, authenticated + tag, roc)
    if decoded_header != header or decoded_payload != plaintext:
        raise RuntimeError("SRTP packet round-trip self-test failed")
    print("RFC 6188 KDF and SRTP packet self-tests passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("self-test")

    derive_parser = subparsers.add_parser("derive")
    derive_parser.add_argument("master_material", help="32-byte key + 14-byte salt as hex")

    decrypt_parser = subparsers.add_parser("decrypt-rtp")
    decrypt_parser.add_argument("master_material", help="32-byte key + 14-byte salt as hex")
    decrypt_parser.add_argument("packet", help="complete SRTP packet as hex")
    decrypt_parser.add_argument("--roc", type=int, default=0, help="rollover counter")
    args = parser.parse_args()

    if args.command == "self-test":
        self_test()
        return

    material = decode_hex(args.master_material, MASTER_KEY_LENGTH + MASTER_SALT_LENGTH)
    if args.command == "derive":
        for name, value in derive_session_keys(material).items():
            print(f"{name}={value.hex()}")
        return

    if not 0 <= args.roc <= 0xFFFFFFFF:
        raise ValueError("ROC must fit in 32 bits")
    header, plaintext = decrypt_rtp(material, decode_hex(args.packet), args.roc)
    print(f"header={header.hex()}")
    print(f"payload={plaintext.hex()}")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
