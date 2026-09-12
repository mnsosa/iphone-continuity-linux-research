# Findings

## 2026-09-12: Connected And Idle Baseline

### USB composite device

- Status: **CONFIRMED**
- Observation: The connected iPhone enumerates as Apple `05ac:12a8`, USB 2.0 high speed, with six configurations. The active configuration is 6 while the device property `kUSBPreferredConfiguration` is 3.
- Method: `system_profiler SPUSBDataType -detailLevel full`, `ioreg -p IOUSB -l -w0`, and `ioreg -r -n iPhone -l -w0`.
- Evidence: Configuration 6 exposes PTP, Apple USB Multiplexor, AppleUSBEthernet, and two CDC-NCM control/data pairs.
- Interpretation: Continuity Camera over this cable is not a standard USB Video Class webcam.
- Next experiment: Snapshot before, during, and after `AVCaptureSession.startRunning()` to test whether configuration 6 or alternate settings change.

### USB interfaces in configuration 6

- Status: **CONFIRMED**
- Observation: Interface 0 is PTP `06/01/01`; interface 1 is Apple USB Multiplexor `ff/fe/02`; interface 2 is AppleUSBEthernet `ff/fd/01`; interfaces 3/4 and 5/6 are CDC-NCM control/data pairs `02/0d/00` and `0a/00/01`.
- Method: `ioreg -r -n iPhone -l -w0`.
- Evidence: NCM data interfaces 4 and 6 each have two endpoints and active alternate setting 1. NCM control interface 3 has one endpoint; control interface 5 reports zero endpoints.
- Next experiment: Preserve complete IORegistry snapshots at each AVFoundation phase and compare all interface, alternate-setting, and transfer-counter properties.

### Network mapping

- Status: **CONFIRMED**
- Observation: AppleUSBEthernet maps to `en8` and is inactive. NCM data interface 4 maps to `en11`; NCM data interface 6 maps to `en10`.
- Method: IORegistry parent/child traversal and `ifconfig -a`.
- Evidence: `en11` has an IPv4 link-local address (`169.254.x.y`) plus IPv6 link-local addressing. `en10` is active and IPv6-link-local-only. Its NCM parent has `HiddenInterface=Yes`; the first pair instead has `HiddenConfiguration=Yes`.
- Next experiment: Capture `en8`, `en10`, and `en11` independently during a camera session and compare byte/packet deltas.

### Discovery service on hidden NCM

- Status: **CONFIRMED**
- Observation: Bonjour advertises `_remoted._tcp.local`, instance `ncm`, on interface index 30.
- Method: `dns-sd -B _remoted._tcp local.` correlated with `ifconfig`; interface index 30 is `en10`.
- Evidence: The browse result was `Add ... if=30 ... _remoted._tcp. ncm`. Resolution returned `<device-hostname>.local.:54644` (hostname redacted); the port is dynamic and is recorded only as this baseline instance.
- Interpretation: The hidden auxiliary NCM link participates in Apple Remote Service Discovery/Rapport discovery before AVFoundation opens the camera.
- Next experiment: Resolve the service, capture its TCP flow, and correlate it with `remoted`, `rapportd`, and `ContinuityCaptureAgent` logs and sockets.

### Participating software

- Status: **HIGH CONFIDENCE**
- Observation: `usbmuxd` owns USB interface 1. `remoted`, `ContinuityCaptureAgent`, `cameracaptured`, the CoreMediaIO register assistant, and `rapportd` are running in idle state. `rapportd` listens on a dynamic TCP port and UDP 3722, but current idle socket output does not by itself prove which sockets belong to this iPhone.
- Method: IORegistry, `ps`, and `lsof -nP -iTCP -iUDP`.
- Next experiment: Diff process/socket snapshots and unified logs across exact probe phase markers.

### Reproducing Apple's USB mode switch

- Status: **HIGH CONFIDENCE** for the USB mode mechanism; **SPECULATION** for Linux Continuity Camera sufficiency.
- Observation: Current libimobiledevice `usbmuxd` source models Apple modes 1 through 5. It identifies six configurations as mode 4, "USB Ethernet + CDC-NCM". It gets the current mode with vendor request `0x45` and sets a mode with vendor request `0x52`, using the desired mode as `wIndex`.
- Method: Source inspection of `src/usb.c` and `src/usb.h` in `libimobiledevice/usbmuxd`.
- Evidence: `APPLE_VEND_SPECIFIC_GET_MODE=0x45`, `APPLE_VEND_SPECIFIC_SET_MODE=0x52`; GET uses device-to-host vendor request semantics, `wLength=4`; SET uses `wIndex=desired_mode`, `wLength=1`.
- Corroboration: `go-ios/ncm/usb.go` independently issues control requests decimal 69 (`0x45`) and 82 (`0x52`) with `wIndex=3`, then activates USB configuration 5 and claims class-10 NCM data endpoints.
- Next experiment: Capture initial attachment on macOS, including the control endpoint, to verify which mode (`wIndex`) macOS requests for this iOS version and how mode 4 leads to active configuration 6.

## 2026-09-12: First Controlled Stream

### Media transport attribution

- Status: **CONFIRMED**
- Observation: During 16.26 seconds of active media, the dominant flow was IPv6 link-local UDP on hidden NCM interface `en10`, iPhone port 65212 to Mac port 49721. It carried 6,423 RTP version 2 packets with payload type 100 and SSRC `0x1e33cb9f`, plus RTCP types 200, 201, and 204 in both directions.
- Evidence: `network/en10.pcap`, `network-analysis.json`, socket ownership snapshots, and matching `RPStreamSession` logs naming local port 49721 as `ContinuityCaptureMediaIdentifierDefaultVideo`.
- Negative evidence: `en8`, `awdl0`, and `llw0` captured zero packets; `en11` carried only 102 packets. No USB configuration, alternate-setting, interface-class, or ownership change occurred between idle and streaming snapshots.
- Interpretation: Wired Continuity Camera media is IP over the hidden CDC-NCM interface, not UVC, direct USB bulk video, or AWDL in this run.

### Codec and protection

- Status: **CONFIRMED** for HEVC and the AES-256-CM/HMAC-SHA1-80 SRTP profile.
- Observation: AVConference configured payload type 100, codec type 102, SRTP cipher suite 7, and identical 46-byte send/receive media keys. Decoder logs explicitly identify 1920x1080 HEVC. Runtime invocation of `+[VCMediaStreamTransport getSRTPMediaKeyLength:7]` returns 32, and disassembly shows `getCryptoSet:withMediaKey:` adding and splitting exactly 14 salt bytes.
- Authentication evidence: SRTCP APP packets are exactly 14 bytes longer than their RTCP header-declared size: four bytes of SRTCP index plus a ten-byte authentication tag. Suite 7's transform-policy branch independently sets tag length `0x0a`.
- Named-suite evidence: AVConference's ordered cipher-name table identifies suite 7 as `SRTP_CIPHER_AES_256_AUTH_SHA1_80`, and `SRTPCipherSuiteForVCMediaStreamCipherSuite:` maps media suite values 0 through 9 directly to the corresponding SRTP suite values.
- Interpretation: The named suite, 32-byte key, 14-byte salt, and 80-bit authentication tag match RFC 6188 `AES_256_CM_HMAC_SHA1_80`.
- Security note: unified logging redacts the middle of the key, so the existing pcap cannot yet be decrypted.

### RTP timing and packet continuity

- Status: **CONFIRMED**
- Observation: The stream contains 6,423 unique consecutive RTP sequence numbers with no gaps, 490 unique timestamps, 490 marker packets, and an invariant timestamp increment of 800 per frame.
- Interpretation: Marker boundaries correspond one-to-one with video frames and establish a 24 kHz RTP clock at 30 frames per second. The capture itself lost no media packets within the observed sequence span.

### Rapport session layout

- Status: **CONFIRMED** for stream names/types/security; **LIKELY** for detailed command/data semantics.
- Observation: `CMContinuityCaptureRapportClient` activates service `com.apple.continuitycapture`. Rapport creates PSK-protected TCP `RPCnx` sessions named `ContinuityCaptureControl`, `ContinuityCaptureCommand`, and `ContinuityCaptureData`, plus UDP `UDPNWPath` sessions for default video, Desk View, and microphone.
- Evidence: Unified logs map Control to local/peer 54194/65191, Command to 54195/65192, Data to 54196/65193, default video to 49721/65212, Desk View to 59637/58079, and microphone to 50690/64504. The pcap records 5,506, 299,568, and zero TCP payload bytes respectively for the three RPC connections.
- Interpretation: Control carries property updates. Command is the strongest candidate for activation and AVConference negotiation. Data remained unused for ordinary video in this run and may support still images or another optional data path.

### Continuity authentication

- Status: **CONFIRMED** for this Mac/iPhone pair.
- Observation: Before stream creation, `rapportd` performs four-message Pair-Verify and resolves the peer as `SameAccountDevice`, with `RPIdentity` authentication and owner status.
- Interpretation: USB trust and transport reachability are not the complete protocol. A Linux implementation must either reproduce this identity path or prove experimentally that a different wired pairing mode is accepted.

### Private-framework object path

- Status: **CONFIRMED** for exposed runtime structure; behavior remains to be reproduced independently.
- Observation: A local Objective-C runtime dump shows that `CMContinuityCaptureRapportClient` owns `RPRemoteDisplaySession` and `RPStreamServer`; each media wrapper implements `cipherKeyforSessionID:` over an `RPStreamSession`; `RPStreamSession` contains `streamKey` and PSK state; AVConference consumes send/receive keys in `VCMediaStreamConfig` and initializes SRTP in `VCMediaStreamTransport`.
- Method: `scripts/dump-private-runtime.sh`, which loads dyld-cached private frameworks and enumerates Objective-C metadata without modifying system files.
- Next experiment: recover the keyed archive from a decrypted command exchange, compare its `sessionID` with the derived salt, and validate media decryption with a newly captured stream key.

### Rapport media-key distribution

- Status: **CONFIRMED** for `UDPNWPath` generation, transport field, client acceptance, and Continuity Capture key construction.
- Observation: `-[RPStreamSession _serverUDPNWPathStartRequest:options:responseHandler:]` calls `NSRandomData(32)`, stores the result at the `_streamKey` ivar, and inserts it into the path-setup response. The dictionary key at that call site resolves at runtime to the string `_streamKey`. `-[RPStreamSession _clientUDPNWPathStartResponse:options:localEndpoint:nwInterface:selfIPString:usb:completion:]` reads that field as `CFData`, accepts it when its length is at least 32 bytes, and stores it in the same ivar.
- Continuity derivation: `cipherKeyforSessionID:` calls `_CMContinuityCaptureCreateCipherKey(streamKey, sessionUUID)`. That function requires `streamKey.length == 32`, copies all 32 bytes, and appends the first 14 UUID bytes to produce AVConference's 46-byte SRTP master key and salt.
- Interpretation: The media key is not derived from Pair-Verify or a Rapport HKDF. Pair-Verify protects/authorizes the parent exchange; the receiver-side Rapport stream server independently chooses the media key and distributes it in the setup response. A Linux receiver therefore does not need an Apple secret to derive SRTP material after it has passed authentication and reached stream setup.

### Media session UUID and RPC serialization

- Status: **CONFIRMED** for object creation, keyed-archive field, RPC wrapper key, byte order, and AVConference consumption.
- Creator: `CMContinuityCaptureRapportClient` lazily creates a fresh `NSUUID` during first entity activation (`objc_opt_new` at `0x22C5B1AF8`) and assigns it to `CMContinuityCaptureConfiguration.sessionID` at `0x22C5B1B0C`. The configuration's plain `init` at `0x22C5AB634` does not create it.
- Serialization: The configuration secure-codes `_sessionID` at offset `0x50` as an `NSUUID` under keyed-archive key `sessionID` (`0x22C5ABB98`-`0x22C5ABBA8`). `infoToRelayAtSessionStart:` places that archive under outer Rapport key `ContinuityCaptureRapportClientPreStartConfigurationKey` (`0x22C5B1238`-`0x22C5B126C`).
- Name collision resolved: Outer key `ContinuityCaptureRapportClientSessionIDKey` carries an `NSNumber` built from a separate integer Rapport-client session ID (`0x22C5B0C28`-`0x22C5B0C60`); it does not carry the media UUID.
- Byte order: `_CMContinuityCaptureCreateCipherKey` asks `NSUUID` for its 16 canonical bytes at `0x22C5831E0` and appends the first 14 directly at `0x22C5831E4`-`0x22C5831FC`. There is no byte swap or UUID-field reordering.
- Consumer: Both audio and video pass `configuration.sessionID` into `cipherKeyforSessionID:` and install the resulting `NSData` as both send and receive media keys. `VCMediaStreamTransport.setupSRTP` later reads those fields at `0x1B7EAA600` and `0x1B7EAA620`; `getCryptoSet:withMediaKey:` validates and splits the bytes into the selected master-key length followed by the 14-byte salt.

### Command-stream RPC schema

- Status: **CONFIRMED** for envelope keys, selectors 1-3, start/stop/event argument ordering, secure coding, OPACK encoding, and encrypted framing; partial for less common selectors.
- Envelope: All stream messages are Foundation dictionaries keyed by `ContinuityCaptureSelector` and `ContinuityCaptureArgs`, with optional `ContinuityCaptureGID`. These strings were resolved by loading the exported constants in the runtime probe rather than inferred from symbol names.
- Selector 1: `ContinuityCaptureControl` carries one `NSData` argument produced by secure-coding a `CMContinuityCaptureControl`; the receiver permits exactly one argument and unarchives that class.
- Selector 2: `ContinuityCaptureControl` carries `[NSNumber(entity), NSData(negotiation)]`. The observed negotiation data is a binary plist, and its nested AVConference models are protobuf-generated `PBCodable` classes.
- Command selector 1: start-stream carries `[secureArchive(configuration), NSNumber(option), NSNumber(0)]`. The receiver requires exactly three arguments, unarchives index 0 as `CMContinuityCaptureConfiguration`, consumes index 1 as the option, validates index 2 as an `NSNumber`, and otherwise ignores index 2.
- Command selector 2: stop-stream carries `[NSNumber(entity), NSNumber(option), NSNumber(0)]`; index 2 is likewise a validated reserved value.
- Command selector 3: event delivery carries exactly `[NSString(eventName), NSNumber(entity)]` and routes connection-disconnect and state-machine events. It is not the start-stream selector.
- Rapport encoding: `RPConnection` wraps each event as `{"_c": event, "_i": eventID, "_t": 1, "_x": xid}` and calls `OPACKEncoderCreateData`. The encrypted TCP record has a four-byte `type || length_be24` header used as AEAD AAD, followed by ciphertext. Normal type is `0x08`; `0x0c` is the Bluetooth high-priority variant. The receive path decrypts first and then calls `OPACKDecodeData`.
- Session bootstrap: `ContinuityCaptureSessionEventID` message type 0 includes the integer session ID, secure-coded pre-start configuration, and stream setup declarations. Each declaration is message type 2 and identifies a stream plus whether it is media. Session termination is message type 4.
- Interpretation: The application-level object graph and record boundary needed for a minimal receiver can be reproduced without decrypting the historical pcap. Remaining Rapport work is cryptographic session setup and an interoperable OPACK implementation, not identification of the serialization format.

### Rapport stream AEAD layer

- Status: **CONFIRMED** for the `main` stream cipher, HKDF-SHA512 key derivation, per-direction labels, nonce discipline, and frame-header AAD; **LIKELY** for the analogous `hipri` labels.
- Streams: `CUPairingSession` opens `main` and `hipri` streams on Pair-Verify completion through `openStreamWithName:type:error:` (type 1). Each `CUPairingStream` carries independent 12-byte encrypt/decrypt nonces, an `authTagLength`, and `encryptData:aadData:error:` / `decryptData:aadData:error:`.
- Cipher: The `main` stream uses ChaCha20-Poly1305 with a 16-byte tag. This corrects the earlier uncertainty around `CryptoAEADCreate(1/2)`. The negotiation capture shows the Mac as `PairVerifyClient` (session type 3) and the peer advertising `_cf = 512`, so the AES-GCM bit `0x20000000` is not set.
- Key derivation: `-[CUPairingSession deriveKeyWithSaltPtr:...]` wraps `PairingSessionDeriveKey` (`0x19d73a320`) and only forwards arguments and validates the return. It produces two 32-byte keys via HKDF-SHA512 with an empty salt over the final Pair-Verify secret, with ASCII info labels `ClientEncrypt-main` and `ServerEncrypt-main`.
- Nonce: Each direction has an independent 96-bit nonce, initialized to zero and incremented little-endian per record; the nonce is not transmitted.
- AAD: The four-byte Rapport frame header `0x08 || length_be24` is the AEAD associated data for each record.
- Verification: `scripts/rapport-aead.py` implements HKDF-SHA512 derivation, little-endian nonce counters, and ChaCha20-Poly1305 with the frame-header AAD, using the `cryptography` package managed by `uv`. Its `self-test` confirms the two derived keys differ, the zero/little-endian nonce behavior, AEAD round-trips with frame AAD, and that both AAD and nonce mismatches fail authentication.
- Interpretation: With the confirmed recipe, decrypting the historical encrypted RPC becomes feasible once the Pair-Verify shared secret is reconstructed; the remaining blocker for full end-to-end validation is obtaining a `RPIdentity` / `SameAccountDevice`-compatible identity, not the AEAD construction.
- Next experiment: Verify the `hipri` labels and confirm client/server key orientation against a decoded record; test whether the same recipe decrypts a captured Continuity RPC frame once the secret is available.

### pymobiledevice3 applicability

- Status: **CONFIRMED** from source inspection.
- Reusable: `_remoted._tcp` browsing with scoped link-local IPv6, RemoteXPC/RSD framing and service discovery, CoreDevice Pair-Verify mechanics, and userspace tunnel infrastructure.
- Limitation: Its Pair-Verify is CoreDevice trusted-host pairing using local Ed25519 pair records. It contains no Rapport `RPIdentity`, `SameAccountDevice`, or Apple Account identity implementation, and it does not implement Continuity Camera RPCs.
- Additional gaps: its pairable-host responder rejects device-initiated Pair-Verify, binds IPv4 only, omits link-local IPv6 from advertisements, and assumes the operating system has already exposed the NCM interface.
- Interpretation: It is strong lower-layer prior art but does not remove the principal Continuity authentication blocker.

## 2026-09-12: Rapport Identity Storage (Plan B Feasibility)

### RPIdentity key backing: SEP vs keychain

- Status: **CONFIRMED** for the two code paths and the runtime flag value on this Mac; **LIKELY** for which path Pair-Verify actually used.
- Question: For a "copy credentials from a verified Mac" plan B, is the Rapport long-term identity key exportable (software/keychain) or Secure Enclave-backed (non-exportable)?
- Method: Runtime disassembly via LLDB against the loaded `Rapport` dyld-cache image, using `macos-probe/build/runtime-dump` as the target. No `sudo`, no secret material read.
- Two backings exist: `RPIdentity` carries both a SEP path and a keychain path. SEP: ivar `_sepPrivateKey` (`SecKeyRef`, offset `0xb0`), getter `sepPrivateKey`, `updateWithSEPPrivateKey:`, and `_edPKDataFromSEPPrivateKey:` which only calls `SecKeyCopyPublicKey` + `SecKeyCopyExternalRepresentation` (it derives the public key; the private key never leaves the enclave). Keychain: `updateWithKeychainItem:error:` reads `metadata`, `secrets`, `identifier`, and `type` from a keychain item and maps the identity `type` string to an integer (`RPIdentity-SameAccountDevice` -> 2, `-Self` -> 1, `-FamilyAccount` -> 3, `-FamilyDevice` -> 4, `-FriendAccount` -> 5, `-FriendDevice` -> 6, `-PairedAccount` -> 7, `-PairedDevice` -> 8, `-SharedTVUserDevice` -> 12).
- Runtime flag: Invoking `+[RPIdentity _sepBackedIdentityEnabled]` in-process returned `0` (false) on this Apple Silicon Mac mini M4. The method is a `dispatch_once`-guarded global; the fast path returns zero. This means SEP-backed identity is not the enabled mode here, so the identity key is expected to live as keychain `secrets` rather than exclusively in the Secure Enclave.
- Consequence for plan B: A keychain-backed identity is, in principle, exportable. The identity a peer presents as `SameAccountDevice` therefore may be copyable as a keychain item (`metadata` + `secrets` + `identifier` + `type`) from a verified Mac into a Linux receiver's own store, instead of reproducing Apple Account enrollment. This is the strongest lever found so far for the authentication blocker.
- Caveats and unknowns: (1) It is not yet confirmed that Pair-Verify used the keychain identity rather than SEP in the captured session; `_pairVerifyUsedIdentity` / `_pairVerifyIdentityType` ivars record this per-run and were not yet read. (2) The keychain item almost certainly lives in a system keychain / restricted access group (`accessGroups` is read in `updateWithKeychainItem:`), so extraction needs `sudo` and appropriate entitlements, and may itself be ACL-protected. (3) The `secrets` field format (raw Ed25519 seed vs wrapped) is not yet decoded. (4) Copying real account identity material has Apple ToS and account-security implications.
- Next experiment: Read `_pairVerifyUsedIdentity` and `_pairVerifyIdentityType` from a live Pair-Verify (or the captured session's logs) to confirm the keychain path was used; then, with explicit approval, locate the Rapport identity keychain item (label/access group) to confirm the `secrets` are readable and determine the private-key encoding.

## Confidence Labels

- **CONFIRMED**: Directly observed and reproducible evidence supports the statement.
- **HIGH CONFIDENCE**: Multiple observations support the statement, but a decisive control is still missing.
- **LIKELY**: Best current explanation with incomplete evidence.
- **SPECULATION**: A testable idea, not a result.
- **DISPROVEN**: Evidence contradicts the statement.
