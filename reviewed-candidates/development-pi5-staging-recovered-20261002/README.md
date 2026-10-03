# Recovered development-Pi staging proposal

This proposal packages the September 15 candidate's recovered bytes at new,
explicit immutable store paths. It preserves the campaign plan, baseline
artifact set, all four payload sizes/digests, partition GUIDs and geometry.
The six missing original store paths remain missing; this is a reviewed
replacement binding, not a restoration of their Nix identities.

The proposed staging plan changes the NVMe disk identity from the original
`bb5289ea-2c0b-424f-a4c7-23c8fdf1ebae` to the independently captured
`b268f110-7d11-47c7-9bcc-2c4b480e4404` and rerenders its GPT bytes.
Its plan digest is
`sha256:fab535df53ce4204d99e787c449e072971f0d88eac504a63ee67a470a7d1c766`.
The original staging plan and signed candidate remain retained. Adopting this
storage reconciliation requires operator review. No physical execution is
authorized by these files or by merging them.

`bindings.json` records the actual build from main commit
`c4b9dcf9b0460cca889e4555c75a1f9a20f70754`, the complete SD runtime closure,
independent source and whole-partition hashes, and the remaining physical
gates. `sd.nix` reproduces that SD package from the retained registered inputs.
The raw payloads and package archive belong in protected retention outside Git.

`descriptor.json` is the existing bounded public native-export interface. The
descriptor constructor and an independent check both passed the production Go
staging-plan parser and hashed the actual release image including its complete
zero tail. A separate check rehashed every SD and NVMe payload and partition.

The previous [native export](https://github.com/PseudoDesign/kaiba-provisioning/actions/runs/37048987102)
has a different fixed configuration binding. Its component correctly rejects
this descriptor and remains valid only for its original descriptor. PR #101
committed this proposal to main as
`733bc29ecbf0a003f03b7eebf1cf3e882ba0110d`; the matching
[native ARM export](https://github.com/PseudoDesign/kaiba-provisioning/actions/runs/37085920334)
completed and was independently verified. The reproducible export interface is:

```console
gh workflow run native-staging-component.yml --repo PseudoDesign/kaiba-provisioning --ref main \
  -f source_sha=733bc29ecbf0a003f03b7eebf1cf3e882ba0110d \
  -f descriptor=reviewed-candidates/development-pi5-staging-recovered-20261002/descriptor.json
```

Verify the actual CI revision, native runner, GitHub archive digest, exact
descriptor, final executable manifest and every exported NAR before importing
the component. `assemble.nix` then uses the existing assembly constructor to
restore the complete NVMe configuration/plan/payload closure. It accepts the
verified immutable component and its exact native CI source revision, and
performs file-only validation on x86 without executing ARM code. The accepted
complete NVMe assembly is
`/nix/store/2h2yma27znryjjm6hnhqh6q6q2vzpgad-kaiba-pi-local-nvme-campaign-stage-assembled`.
Its seven-object closure retains the native CI component bytes and exact ARM
references. The combined SD/NVMe and descriptor archive contains 15 paths;
every NAR hash, size and reference matched independent reimport. See the
[October 3 status record](status-20261003.json) for its retained archive binding.
The original `bindings.json` remains a record of the earlier preparation.

The current provisioner's Nix store is read-only. Its `/tmp` has about 510 MB
available and `/var` about 268 MB; no separate writable disk is attached.
The operator selected and activated malak backing storage over the isolated
USB link (`10.0.0.1` to `10.0.0.2`). The [malak storage worksheet](malak-storage.md)
records successful NFSv4 content, ownership, capacity and synchronized readback
checks. The exact fixed Nix paths and native command were qualified in a private
read-only mount namespace, preserving the global store. Synthetic staging file
operations and a complete 64 MiB snapshot matched fresh client and independent
host readback. These checks do not replace actual recovery range backups.
Revalidate at least 24 GiB free, all runtime digests and the protected transport
before physical preparation. The target NVMe cannot hold its own runtime or
backups.
Keep physical preparation directories root-owned as required by the staging
tool; the operator-owned public retention directory is a separate handoff.

Forty historical public artifacts were exported, independently rehashed and
retained with all offline review inputs. All four owned-recovery bundles passed
customer-signature and exact EEPROM/plan/result checks. Three release receipt
exports, including v0.1.15, passed complete five-receipt verification against
independent registries and signing results; v0.1.4 still needs its original
registry snapshot. The recovered hardware records report an unset customer key
and no mutation. Their fingerprint correlates with later owned readbacks of
this Pi, but they do not establish the original ownership operation. The manual
lane rehearsal provides no automated fail-off proof. Exact retention bindings
and assurance limits are in the [October 3 status record](status-20261003.json).

The SD remains active in the Pi and lacks its inactive malak capture. Original
ownership evidence, recovery backups, approved profile, RTC, authority
certificate/availability, power topology and explicit physical execution
approval remain open. All physical run, claim, security and readiness flags
remain false. See [the task record](../../docs/task1-physical-acceptance.md).
