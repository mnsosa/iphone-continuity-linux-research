# Prior Art Triage

These are code leads, not evidence that Continuity Camera has already been implemented on Linux.

## Directly Relevant Lower Layers

### libimobiledevice/usbmuxd

- Repository: <https://github.com/libimobiledevice/usbmuxd>
- License: GPL-3.0
- Concrete value: Implements Apple USB mode discovery and switching. Source comments distinguish initial, Valeria/H.265 capture, CDC-NCM, USB Ethernet plus CDC-NCM, and direct NCM modes.
- Immediate use: Reproduce the mode/configuration transition on Linux rather than inventing the vendor control requests.

### go-ios NCM

- Repository: <https://github.com/danielpaulus/go-ios/tree/main/ncm>
- License: MIT
- Concrete value: Userspace CDC-NCM endpoint claim, NCM16 framing, and TAP bridging. It uses Apple requests `0x45` and `0x52`, activates configuration 5, then selects a class-10 data interface.
- Limitation: Its single-NCM/configuration-5 assumptions do not directly match the locally observed mode-4/configuration-6 device with two NCM pairs.

### Linux ipheth

- Source: <https://github.com/torvalds/linux/blob/master/drivers/net/usb/ipheth.c>
- License: dual BSD/GPL
- Concrete value: Existing Apple Ethernet support and Apple-specific NCM receive handling.
- Limitation: Binding the visible Apple Ethernet interface is not equivalent to exposing the hidden auxiliary NCM link observed on macOS.

### iphone-continuity-camera-fix

- Repository: <https://github.com/yoy123/iphone-continuity-camera-fix>
- License: MIT
- Concrete value: Reports that wired Continuity Camera fails when `usbmuxd` does not enter the NCM-bearing mode. Its Objective-C hook names private classes and selectors such as `CMContinuityCaptureDiscoverySession`, `CMContinuityCaptureProvider`, transport `startStream`, and Rapport device filtering.
- Caveat: It targets unsupported OCLP Macs, uses binary patching and injection, and is not a receiver implementation. Class/selector names are useful leads but require independent validation on this host.

## Adjacent Protocol Implementations

### pymobiledevice3

- Repository: <https://github.com/doronz88/pymobiledevice3>
- License: GPL-3.0-or-later
- Concrete value: Implements `_remoted._tcp` browsing over scoped link-local IPv6, Remote Service Discovery, RemoteXPC framing, CoreDevice trusted-host Pair-Verify, and userspace tunnel infrastructure. These are reusable references for the hidden NCM bootstrap and transport layers.
- Limitation: Source inspection found no Rapport `RPIdentity`, `SameAccountDevice`, Apple Account identity, or Continuity Camera RPC implementation. Its pairable-host responder also rejects device-initiated Pair-Verify and is not ready for an IPv6-link-local-only NCM listener without changes.

### furiousMAC/continuity

- Repository: <https://github.com/furiousMAC/continuity>
- License: GPL-2.0
- Concrete value: BLE Continuity advertisement decoding and discovery context.
- Limitation: No Continuity Camera video receiver.

### OWL / AWDL research

- Repository: <https://github.com/seemoo-lab/owl>
- Concrete value: Open AWDL implementation for wireless comparison experiments.
- Limitation: The immediate experiment is wired, and local evidence already exposes a USB NCM path.

### UxPlay

- Repository: <https://github.com/FDH2/UxPlay>
- License: GPL-3.0
- Concrete value: Apple media receiver architecture, RTSP/RTP parsing, clocking, and H.264/HEVC decoding patterns.
- Limitation: AirPlay protocol behavior must not be projected onto Continuity Camera without packet evidence.

## Current Gap

No reviewed project currently provides the missing end-to-end path from Rapport Continuity camera discovery through authenticated stream negotiation to decoded camera frames on Linux. The immediate high-value boundary is between `_remoted._tcp` discovery and private Continuity capture stream setup.
