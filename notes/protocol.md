# Protocol Notebook

The first capture identifies the transport stack and active video flow. Static analysis now also identifies the RPC object encoding and encrypted frame boundary; historical payload decryption remains unresolved.

## Candidate Channel Table

| Channel | Current evidence | Function | Confidence |
|---|---|---|---|
| `_remoted._tcp` on hidden NCM | Advertised in idle state on `en10`; resolved to a dynamic iPhone TCP port | Discovery / Rapport bootstrap | CONFIRMED |
| Rapport link | `rapportd` TCP flow; Pair-Verify M1-M4 succeeds as `SameAccountDevice`, auth flag `RPIdentity`, owner flag | Authentication and encrypted Rapport messaging | CONFIRMED |
| `ContinuityCaptureControl` | Rapport `RPCnx`, local `54194`, peer `65191`, `PSK yes`; 5,506 TCP payload bytes | Asynchronous control/property updates | HIGH CONFIDENCE |
| `ContinuityCaptureCommand` | Rapport `RPCnx`, local `54195`, peer `65192`, `PSK yes`; 299,568 TCP payload bytes | Commands and AVConference negotiation | LIKELY |
| `ContinuityCaptureData` | Rapport `RPCnx`, local `54196`, peer `65193`, `PSK yes`; no TCP payload in this run | Data/still-image path or reserved channel | LIKELY |
| Default video | Rapport `UDPNWPath`, local `49721`, peer `65212`; 6,423 RTP PT=100 packets, SSRC `0x1e33cb9f` | HEVC video over SRTP | CONFIRMED |
| Default video RTCP | Same UDP 5-tuple; packet types 200, 201, and 204 in both directions | Sender reports, receiver reports, and application feedback/control | CONFIRMED |
| Deskcam video | Rapport creates `UDPNWPath` local `59637`, peer `58079`; no attributed media in selected-camera run | Desk View video | HIGH CONFIDENCE |
| Microphone | Rapport creates `UDPNWPath` local `50690`, peer `64504`; no attributed media in selected-camera run | Audio media | HIGH CONFIDENCE |
| usbmux interface | Owned by `usbmuxd`; no streaming-time interface/configuration change | Device services and USB mode setup, not observed media path | CONFIRMED for ownership; camera bootstrap role unresolved |

## Active Video Parameters

- Interface: `en10`, IPv6 link-local.
- Wire format: RTP version 2, dynamic payload type 100, SSRC `0x1e33cb9f`.
- Codec: HEVC, confirmed by the receiver's hardware-decoder logs.
- Protection: SRTP and SRTCP, numeric AVConference cipher suite 7.
- Key material: send and receive values are each 46 bytes and identical in this run. Unified logging reveals only the first and last 16 bytes.
- Runtime mapping: `+[VCMediaStreamTransport getSRTPMediaKeyLength:7]` returns 32. AVConference's `getCryptoSet:withMediaKey:` implementation explicitly splits `keyLength + 14` bytes into key and salt.
- Authentication: SRTCP APP packets contain a 14-byte suffix beyond their RTCP-declared length. Four bytes are the mandatory SRTCP index, leaving a 10-byte/80-bit authentication tag; AVConference's suite-7 transform policy independently sets tag length `0x0a`.
- Profile: **CONFIRMED** AES-256-CM with HMAC-SHA1-80. AVConference's ordered cipher-name table identifies suite 7 as `SRTP_CIPHER_AES_256_AUTH_SHA1_80`; `SRTPCipherSuiteForVCMediaStreamCipherSuite:` maps media suite 7 directly to SRTP suite 7.
- RTP timing: 6,423 unique consecutive sequence numbers with no gaps; 490 frame timestamps and marker packets; fixed timestamp step 800. This establishes a 24 kHz clock at 30 fps.

## Stream Key Lifecycle

- For `UDPNWPath`, the endpoint acting as the Rapport stream server calls `NSRandomData(32)`, stores the result in `RPStreamSession._streamKey`, and places it in the successful path-setup response under the `_streamKey` dictionary key. In the captured Continuity Camera topology, the Mac receiver is that server.
- The client reads `_streamKey` as `CFData`, requires at least 32 bytes, and stores it in its own `RPStreamSession._streamKey`. This is random key distribution, not an HKDF derivation from Pair-Verify.
- `CMContinuityCaptureTransportDeviceRapportStream.cipherKeyforSessionID:` passes the stream key and media session UUID to `_CMContinuityCaptureCreateCipherKey`.
- `_CMContinuityCaptureCreateCipherKey` requires a 32-byte stream key and returns the 46-byte SRTP master material `streamKey || sessionUUID[0:14]`.
- The setup response travels after Rapport authentication. Recovering a historical key from the existing pcap would still require decrypting the parent Rapport exchange or capturing process memory, but a Linux receiver can generate its own stream key when acting as server.

## Media Session UUID Lifecycle

- `CMContinuityCaptureConfiguration.init` does not create the media session UUID; it only initializes configuration state.
- During the first entity activation, `CMContinuityCaptureRapportClient` creates a fresh `NSUUID` with `+[NSUUID new]` and assigns it to `CMContinuityCaptureConfiguration.sessionID`. The static call sites are `objc_opt_new` at `0x22C5B1AF8` and `setSessionID:` at `0x22C5B1B0C`.
- The configured object is subsequently passed to `setupRPDisplaySessionForConfiguration:completion:` at `0x22C5B2270`. `infoToRelayAtSessionStart:` archives it with secure coding at `0x22C5B1238` and stores the archive in the Rapport event under `ContinuityCaptureRapportClientPreStartConfigurationKey` at `0x22C5B125C`-`0x22C5B126C`.
- Inside the keyed archive, `CMContinuityCaptureConfiguration.encodeWithCoder:` reads the `NSUUID` ivar at offset `0x50` and encodes it under the nine-character key `sessionID` at `0x22C5ABB98`-`0x22C5ABBA8`. `initWithCoder:` restricts that field to `NSUUID`, decodes the same key at `0x22C5F00E0`-`0x22C5F00F8`, and stores it back at offset `0x50` at `0x22C5F0104`-`0x22C5F0108`.
- `ContinuityCaptureRapportClientSessionIDKey` is a separate outer event field. The value constructed at `0x22C5B0C28`-`0x22C5B0C60` is an `NSNumber` made from the Rapport client's integer session ID, not the media `NSUUID` used for SRTP salt construction.
- `NSUUID.getUUIDBytes:` writes the UUID's canonical 16-byte representation. `_CMContinuityCaptureCreateCipherKey` appends bytes 0 through 13 directly, with no integer load, byte swap, or field reordering. For UUID text `00112233-4455-6677-8899-AABBCCDDEEFF`, the appended salt is `00 11 22 33 44 55 66 77 88 99 AA BB CC DD`.
- Audio and video use the same configuration UUID but independent Rapport stream keys. Audio derives and installs its key at `0x22C5BB998`-`0x22C5BBA94`; video does so at `0x22C5F45E8`-`0x22C5F46DC`.

## Continuity RPC Envelopes

### Session bootstrap

The Mac sends `ContinuityCaptureSessionEventID` through `RPRemoteDisplaySession` after activating `com.apple.continuitycapture`. The initial message is a Foundation dictionary with these confirmed fields:

| Wire key | Value |
|---|---|
| `ContinuityCaptureRapportClientMessageTypeKey` | `NSNumber(0)` for session bootstrap |
| `ContinuityCaptureRapportClientSessionIDKey` | Rapport client's integer session ID |
| `ContinuityCaptureRapportClientPreStartConfigurationKey` | Secure keyed archive of `CMContinuityCaptureConfiguration`, including media `sessionID` UUID |
| `ContinuityCaptureRapportClientStreamsSetupKey` | Array of stream declarations |

Each stream declaration uses `ContinuityCaptureRapportClientMessageTypeKey = 2`, `ContinuityCaptureRapportClientSetStreamMessageDataIdentifierKey`, and `ContinuityCaptureRapportClientSetStreamMessageDataIsMediaTypeKey`. The identifiers resolve to `ContinuityCaptureControl`, `ContinuityCaptureCommand`, and `ContinuityCaptureData`, plus the media identifiers enumerated from capabilities. Session termination uses message type 4. Incoming dispatch also confirms message types 3 for events, 5 for audio-clock synchronization completion, 6 for capability events, 7 for transport-session signaling, and 9 for reaction effects; their complete field schemas are not yet all mapped.

### Stream commands

Control and command traffic uses `ContinuityCaptureStreamEventID`. `CMContinuityCaptureTransportDeviceRapportStream.sendMessage:message:completion:` passes the Foundation dictionary directly to Rapport `sendEventID:event:options:completion:`. The shared envelope keys resolve as follows:

| Exported symbol | Wire string |
|---|---|
| `ContinuityCaptureClientSelectorKey` | `ContinuityCaptureSelector` |
| `ContinuityCaptureClientArgsKey` | `ContinuityCaptureArgs` |
| `ContinuityCaptureClientGIDKey` | `ContinuityCaptureGID` |

Confirmed selector schemas are:

| Stream | Selector | Arguments |
|---|---:|---|
| `ContinuityCaptureControl` | 1 | One secure keyed archive of `CMContinuityCaptureControl` |
| `ContinuityCaptureControl` | 2 | `[NSNumber(entity), NSData(AVConference negotiation)]` |
| `ContinuityCaptureCommand` | 1 | `[NSData(secure archive of CMContinuityCaptureConfiguration), NSNumber(option), NSNumber(0)]`; the last value is validated but not consumed |
| `ContinuityCaptureCommand` | 2 | `[NSNumber(entity), NSNumber(option), NSNumber(0)]` for stop-stream; the last value is validated but not consumed |
| `ContinuityCaptureCommand` | 3 | `[NSString(eventName), NSNumber(entity)]` for connection and state-machine events |

The selector constants are direct `NSNumber` objects: selector 1 at `0x282D7D640`, selector 3 at `0x282D7D6A0`, and selector 2 at `0x282D7D700`. The negotiation `NSData` observed in logs starts with `bplist00`; the AVConference objects nested below that layer use protobuf-generated `PBCodable` classes. The application-level Foundation object graph is now statically reproducible.

### Rapport object encoding and framing

`RPConnection.sendEncryptedEventID:event:options:completion:` wraps the Continuity event in this Foundation dictionary before encoding:

| Key | Value |
|---|---|
| `_c` | Event payload dictionary |
| `_i` | Event ID string, such as `ContinuityCaptureStreamEventID` |
| `_t` | `NSNumber(1)`, identifying an event |
| `_x` | Monotonically allocated 32-bit transaction ID |

The wrapper is encoded by `OPACKEncoderCreateData`, so OPACK is **CONFIRMED**, not inferred. The normal encrypted TCP frame is `type || length_be24 || ciphertext`: type is `0x08`, the length is the encrypted body length encoded as a 24-bit big-endian integer, and all four header bytes are authenticated as AEAD AAD. A high-priority Bluetooth path substitutes type `0x0c`; it is not the normal Continuity Camera TCP path. The receiver selects the corresponding cryptor from the type byte, authenticates/decrypts with the four-byte header as AAD, calls `OPACKDecodeData`, requires a dictionary, and dispatches by `_t`, `_i`, and `_x`.

### Rapport stream AEAD layer

- Status: **CONFIRMED** for the `main` stream cipher, key derivation, and nonce discipline.
- Streams: On Pair-Verify completion, `CUPairingSession` opens named streams `main` and `hipri` (via `openStreamWithName:type:error:`, type 1). Each `CUPairingStream` holds separate 12-byte encrypt/decrypt nonces, an `authTagLength`, and `encryptData:aadData:error:` / `decryptData:aadData:error:` primitives.
- Cipher: The `main` stream uses ChaCha20-Poly1305 with a 16-byte Poly1305 tag. The Mac was `PairVerifyClient` (session type 3) and the peer advertised `_cf = 512`, so the AES-GCM feature bit `0x20000000` was not set; the cipher stays ChaCha20-Poly1305 rather than AES-GCM.
- Key derivation: `-[CUPairingSession deriveKeyWithSaltPtr:...]` is a thin wrapper over `PairingSessionDeriveKey` (`0x19d73a320`). It derives two independent 32-byte keys with HKDF-SHA512, empty salt, over the final Pair-Verify shared secret, using ASCII info labels `ClientEncrypt-main` and `ServerEncrypt-main`. The client uses `ClientEncrypt-main` to encrypt and `ServerEncrypt-main` to decrypt; the server is symmetric.
- Nonce: Each direction keeps an independent 96-bit nonce, initialized to zero and incremented little-endian by one per record. The nonce is not transmitted.
- AAD: The four-byte Rapport frame header (`0x08 || length_be24`) is fed verbatim as the AEAD associated data for each record, binding the declared length to the ciphertext.
- `hipri` stream: Assumed analogous with labels `ClientEncrypt-hipri` / `ServerEncrypt-hipri` and the same nonce/tag discipline. **LIKELY**, not yet verified against a decoded record.
- Reproducible helper: `./scripts/rapport-aead.py self-test` derives both keys, checks the little-endian nonce, and round-trips ChaCha20-Poly1305 records with the frame header as AAD. `derive`, `encrypt`, and `decrypt` subcommands operate from either a raw 32-byte key (`--key`) or the Pair-Verify secret (`--secret --direction`), with `--frame-aad` reproducing the header AAD. The project is managed with `uv`; run scripts via `uv run python scripts/rapport-aead.py ...`.

## AVConference Key Consumption

- `VCMediaStreamConfig.setSendMediaKey:` stores the data at offset `0x40` (`0x1B7FA3D30`), while `setReceiveMediaKey:` stores it at offset `0x50` (`0x1B7FA3D40`).
- `VCMediaStreamTransport.setupSRTP` reads those exact properties and calls `getCryptoSet:withMediaKey:` for send at `0x1B7EAA600`-`0x1B7EAA610` and receive at `0x1B7EAA618`-`0x1B7EAA630`.
- `getCryptoSet:withMediaKey:` computes the required size as the selected master-key length plus 14 at `0x1B7EA9FD0`-`0x1B7EAA004`, requires an exact-length `NSData` at `0x1B7EAA048`-`0x1B7EAA054`, copies it without transformation at `0x1B7EAA058`-`0x1B7EAA064`, then treats the leading key-length bytes as the master key and the trailing 14 bytes as the master salt at `0x1B7EAA068`-`0x1B7EAA08C`.

## Private Runtime Surface

Runtime enumeration confirms the relevant implementation path without changing macOS:

- `CMContinuityCaptureRapportClient` owns `RPRemoteDisplaySession` and `RPStreamServer`.
- `CMContinuityCaptureTransportDeviceRapportStream` wraps `RPStreamSession` and implements `cipherKeyforSessionID:`.
- `RPStreamSession` stores `streamKey`, `pskData`, stream ID/type, socket, and NW client ID.
- `VCMediaStreamConfig` stores send/receive media keys, RTP/RTCP cipher suites, SSRCs, payload maps, and timestamp rate.
- `VCMediaStreamTransport` exposes `setupRTPWithNWConnection:error:`, `setupSRTP`, and key-length/cipher mapping methods.
- `AVCMediaStreamNegotiator` stores binary-plist offer/answer data and compressed/negotiated AVConference blobs; `VCCallInfoBlob` is a protobuf-generated `PBCodable` carrying call and peer metadata.

The reproducible dump command is `./scripts/dump-private-runtime.sh`; output is generated at `dumps/private-runtime.txt` and intentionally ignored by Git. The dump includes the exported Continuity key symbols and their actual wire strings.

`./scripts/srtp-aes256.py self-test` independently validates the AES-256-CM key derivation implementation against the RFC 6188 vectors. Its `decrypt-rtp` command verifies the 80-bit HMAC-SHA1 tag before decrypting a packet and is ready for a future capture containing the full master material.
