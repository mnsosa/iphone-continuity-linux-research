# Authentication Layers

Keep these mechanisms separate until wire evidence demonstrates a relationship:

1. USB host/device trust and lockdownd pairing records.
2. Apple Account/iCloud identity and peer eligibility.
3. Rapport or Continuity-specific authentication.
4. Per-session key agreement and media encryption.

The presence of usbmux and a trusted USB connection does not demonstrate that lockdownd pairing authenticates Continuity Camera.

## Rapport Pair-Verify Protocol (Plan A)

Reconstructed by static/runtime disassembly of `CUPairingSession` (CoreUtils) and `RPConnection`/`CUPairingIdentity` (Rapport). `RPConnection._clientPairVerifyStart` builds a `CUPairingSession` (session type 3 = PairVerifyClient), sets flags/appInfoSelf, installs `signDataHandler` / `verifySignatureHandler` / `completionHandler`, and activates it. The session runs the state machine and calls back into Rapport for identity signing and verification. Status: **CONFIRMED** for the normal Rapport identity path; optional Apple-account/group extensions are **CONFIRMED present** but their inner TLV numbers are not fully mapped.

### Message flow (HomeKit-style TLV8)

TLV8 framing: one-byte type, one-byte length, values >255 bytes split into repeated same-type fragments (`TLV8BufferAppend` at `0x19d763940`, cap at `0x19d763a38`; reassembly via `TLV8CopyCoalesced`). Sub-payloads are TLV8 even though `RPConnection` events at the outer layer are OPACK.

1. M1 client to server: `State`=1, `PublicKey`(type 3)=client ephemeral X25519 public (32 bytes), optional `Method`(type 0) and `Flags`(type 25), optional `Application info`(type 29 = embedded OPACK dict).
2. M2 server to client: `State`=2, `PublicKey`(type 3)=server ephemeral X25519 public, and `EncryptedData`(type 5). The encrypted sub-TLV (nonce `PV-Msg02`) contains the server `Identifier`(type 1) and `Signature`(type 10, 64-byte Ed25519) over `serverPK || identifier || clientPK`.
3. M3 client to server: `State`=3 and `EncryptedData`(type 5), nonce `PV-Msg03`. Inner TLV holds the client `Identifier`(type 1) and `Signature`(type 10) over `clientPK || identifier || serverPK`.
4. M4 server to client: `State`=4. Normally nothing else; if group info or an Apple-account proof was generated, M4 adds `EncryptedData`(type 5) with those extension TLVs. Nonce `PV-Msg04` normally, or `PV-Msg4s` when pairing flag `0x20000000` is set (still ChaCha20-Poly1305; the flag's exact meaning is unresolved).

### Crypto primitives and labels (quote exactly)

ECDH: X25519/Curve25519, 32-byte keys. The ephemeral private key is not raw random; it is derived: `ephemeralPrivate = HKDF-SHA512(IKM=RandomBytes(32), salt="Pair-Verify-ECDH-Salt", info="Pair-Verify-ECDH-Info", L=32)`, then `cccurve25519_make_pub`. Shared secret `= X25519(ephemeralPrivate, peerPublic)` via `cccurve25519`; all-zero result rejected. Evidence: client `0x19d740cc4`-`0x19d74101c`, server `0x19d742410`-`0x19d742490`.

Pair-Verify encryption key: `HKDF-SHA512(IKM=sharedSecret, salt="Pair-Verify-Encrypt-Salt", info="Pair-Verify-Encrypt-Info", L=32)` (both salt and info are 24-byte strings). Evidence: client `0x19d74104c`-`0x19d741080`, server `0x19d742dd4`-`0x19d742e00`.

Sub-TLV AEAD: ChaCha20-Poly1305, 32-byte key, no AAD, 16-byte tag. Nonces are the 8-byte ASCII labels `PV-Msg02` / `PV-Msg03` / `PV-Msg04` (or `PV-Msg4s`) passed to a 64-bit-counter ChaCha init; equivalent IETF 12-byte nonce is `0x00000000 || <8-byte ASCII label>`.

Identity signatures: Ed25519 (`cced25519_sign` / `cced25519_verify`, SHA-512 internal). `CUPairingIdentity signDataPtr:...` at `0x19d6c82d0` validates 32-byte EdPK/EdSK; `verifySignaturePtr:...` at `0x19d6c80bc` requires 64-byte signature + 32-byte public key. No separate signing KDF/label; the concatenated `PK||identifier||PK` payload is signed directly.

Final stream secret: the raw 32-byte X25519 shared secret (not the Pair-Verify encryption key) is the IKM for `PairingSessionDeriveKey` (`0x19d73a320`, HKDF-SHA512), which produces the `ClientEncrypt-main` / `ServerEncrypt-main` stream keys already documented in `protocol.md`.

### TLV type numbers

0 Method, 1 Identifier, 3 PublicKey, 5 EncryptedData, 6 State, 7 Error, 10 Signature, 25 Flags, 29 Application info (OPACK dict inside TLV8).

### Plan A implication

The wire protocol and all crypto are now reproducible on Linux with standard libraries (X25519, HKDF-SHA512, ChaCha20-Poly1305, Ed25519). The only remaining hard input is the local Ed25519 identity key pair plus the identifier that the iPhone accepts as `SameAccountDevice` (see `findings.md` "Rapport Identity Storage"). Reproducing enrollment to obtain that identity is the open plan A problem; if it proves infeasible, plan B (importing an existing keychain identity) is the fallback.

## SameAccountDevice Enrollment (Plan A verdict)

Status: **CONFIRMED** that SameAccount membership is gated by an Apple-account-issued credential, not by a self-generated key pair. This makes from-scratch Linux enrollment infeasible without account material and pushes the practical path to plan B (import a real credential).

Evidence from CoreUtils runtime disassembly:

1. The Rapport transport identity is a local Ed25519 key pair (`-[CUPairingIdentity setRandomKeyPair]` -> `cced25519_make_key_pair_compat`), and `-[CUPairingDaemon _copyOrCreateWithOptions:error:]` copies-or-creates + persists it (`_saveIdentity:options:`), deriving `altIRK` via HKDF-SHA512. This layer alone is reproducible.
2. But SameAccount classification runs a separate Apple ID layer: `CUPairingSession` holds `_myAppleIDInfoClient` (`CUAppleIDClient`). `-[CUAppleIDClient _getMyCertificateAndReturnError:]` obtains the local identity via `_getMyIdentityAndReturnError:` + `SecIdentityCopyCertificate` + `SecCertificateCreateWithData` — i.e. a keychain `SecIdentity` (X.509 certificate plus its private key) issued for the Apple ID, not the Ed25519 pairing key.
3. `-[CUAppleIDClient validatePeerWithFlags:error:]` fetches the peer certificate (`_getPeerCertificateAndReturnError:`), reads its Common Name (`SecCertificateCopyCommonName`), checks a suffix, keys off `encDsID` (the account Directory Services ID), and calls `_validatePeerHashes:`.
4. `-[CUAppleIDClient _validatePeerHashes:]` computes `CC_SHA256` over lowercased Apple ID emails/phone numbers and matches them against `ValidatedEmailHashes` / `ValidatedPhoneHashes`. `copyMyValidationDataAndReturnError:` produces an `AppleIDAccountValidationRecordData`. This validation record is Apple-issued account attestation data.

Verdict on plan A: The `SameAccountDevice` decision depends on an Apple-issued Apple ID certificate (`SecIdentity`), the account DS ID (`encDsID`), and an Apple ID account validation record (email/phone SHA-256 hashes). None of these can be minted locally, so a Linux device cannot enroll itself into the account from scratch. Plan A is viable only for the transport/crypto layers, not for producing account membership.

Consequence: the fallback (plan B) must import, from a device already signed into the same Apple Account, the Apple ID `SecIdentity` (certificate + private key), its DS ID, and the account validation record — in addition to the Rapport keychain identity already discussed in `findings.md`. Exact extraction and format are unverified and require `sudo` plus explicit approval.
