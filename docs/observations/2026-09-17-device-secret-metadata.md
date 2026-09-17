# Read-only slot inventory: 2026-09-17

The metadata companion succeeded on the existing owned Pi 5 inspection boot:
kernel `6.18.34`, installed EEPROM revision `086b83e3`. The native ARM
executable came from the tested source in PR #33 and ran once from `/run`
tmpfs. It was removed afterward; root verity remained healthy. No kernel,
device permissions, signed image or persistent media changed.

Firmware reported one slot. Slot 1 returned status `0x00000001`
(device-private-key type) and usage `0` (undefined). The READ, GEN, SIGN, HMAC
and USAGE lock bits were not reported set in this inspection boot. Key
contents were not requested. These values do not establish that the slot is
blank, suitable for Kaiba, or supports the proposed HMAC mechanism.

The metadata-access blocker is resolved without a kernel patch. Slot selection
and secret programming still require the existing suitability and authorized
image review. HMAC behavior, lock enforcement, offline encrypted-state reopen
and copied-media confidentiality remain pending. Raw records stay private on
malak; the JSON projection binds their hashes and the exact helper source/build
without publishing device serials or SSH identity details.
