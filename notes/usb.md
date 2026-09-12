# USB

## Baseline Device

| Property | Observed value |
|---|---|
| Vendor/Product | `05ac:12a8` |
| Product | iPhone |
| Speed | 480 Mb/s |
| Number of configurations | 6 |
| Active configuration | 6 |
| Preferred configuration property | 3 |

The experiment stores both text and IORegistry representations at every phase. A future Linux reproduction must determine which vendor request selects the composite/NCM mode; merely binding a generic NCM driver after normal enumeration may not be sufficient.

Relevant prior-art candidates to validate against packet-level evidence are libimobiledevice/usbmuxd USB mode switching, `go-ios/ncm`, and Linux `ipheth`.
