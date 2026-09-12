# Working Architecture

This is a model to test, not a protocol specification.

```text
iPhone USB composite device (configuration 6)
  |-- PTP
  |-- Apple USB Multiplexor -> usbmuxd / lockdownd ecosystem
  |-- AppleUSBEthernet -> en8 (ordinary iPhone USB network service)
  |-- CDC-NCM pair 1 -> en11
  `-- CDC-NCM pair 2 -> en10 (hidden auxiliary link)
                         `-- IPv6 link-local + _remoted._tcp instance ncm
                               `-- remoted / Rapport Pair-Verify (SameAccountDevice)
                                    `-- com.apple.continuitycapture
                                         |-- RPCnx/PSK: Control, Command, Data
                                         `-- UDPNWPath: default video, deskcam, microphone
                                               |-- server-generated 32-byte _streamKey
                                               `-- active default video: HEVC over AES-256-CM/HMAC-SHA1-80 SRTP
```

The confirmed type-`0x08` OPACK records are protected by the Rapport stream AEAD layer: ChaCha20-Poly1305 (16-byte tag) with per-direction HKDF-SHA512 keys (`ClientEncrypt-main` / `ServerEncrypt-main`, empty salt over the Pair-Verify secret), independent 96-bit little-endian nonces starting at zero, and the four-byte frame header as AAD. This resolves open question 1 for the `main` stream. See `notes/protocol.md` and `scripts/rapport-aead.py`.

Open questions:

1. Resolved for `main`: ChaCha20-Poly1305 with HKDF-SHA512 per-direction keys and little-endian nonces (see above). Remaining: confirm the `hipri` labels and reconstruct the Pair-Verify shared secret to decrypt captured records.
2. Is USB trust sufficient under any wired eligibility mode, or is SameAccount identity always required? Resolved: SameAccount is gated by an Apple-account-issued credential (Apple ID `SecIdentity` certificate + DS ID `encDsID` + account validation record with email/phone SHA-256 hashes), verified by `CUAppleIDClient validatePeerWithFlags:`. A self-generated key pair is not sufficient, so from-scratch Linux enrollment (plan A) cannot produce account membership; plan B must import that Apple-issued material. See `notes/authentication.md`.
3. Which USB vendor-mode request and configuration transition occur at initial attachment?
