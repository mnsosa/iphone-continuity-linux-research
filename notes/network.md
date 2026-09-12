# Network

Current candidate interfaces are discovered dynamically, but the initial host mapping is:

| Interface | USB parent | Initial state |
|---|---|---|
| `en8` | AppleUSBEthernet interface 2 | inactive |
| `en11` | CDC-NCM data interface 4 | active, IPv4 + IPv6 link-local |
| `en10` | CDC-NCM data interface 6 | active, hidden, IPv6 link-local |

The runner captures each candidate separately, plus `awdl0` and `llw0`, to avoid prematurely attributing media to USB NCM.
