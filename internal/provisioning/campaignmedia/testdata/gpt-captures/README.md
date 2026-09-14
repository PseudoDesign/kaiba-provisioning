# GPT metadata regression captures

This corpus lets the production GPT parsers replay device metadata without
hardware access or hashing multi-gigabyte payload ranges. Each
`NAME.capture.json` has a separately reviewed `NAME.expect.json`. The Go tests
discover these pairs automatically and check header and entry CRCs, reciprocal
geometry, the fixed campaign policy, and any distinct physical-end lineage.
Missing bytes are errors; the reader never supplies invented zero payloads.
The full inspector and payload-mutation tests remain in the package.

The initial `reconstructed-aligned-nvme` fixture is **synthetic**, generated from
`newInitialGPTAlignedNVMeFixture` at commit
`14e82b2ffb23abc319e9f9a740b26970f392a173`. Its primary-header CRC32
`82ec0f8d` and entry-array CRC32 `42c0e789` match values recorded by the earlier
physical diagnostic. Its bytes and SHA-256 hashes are reconstructed, not
physical readback. No raw physical GPT capture is currently checked in.

## Capture and import

From the repository root, export an existing image file with:

```sh
python3 scripts/diagnostics/gpt-capture/capture.py \
  --source /path/to/exported-device.img \
  --description 'Source image, observation reference, device description, and originating revision' \
  > /tmp/reviewed-device.capture.json
```

On Linux the same tool accepts a block-device source opened read-only. It exports
at most 50 KiB of metadata: the first 34 sectors, the 33 sectors ending
at the primary header's declared backup, and the final 33 physical sectors.
Overlapping regions are merged. Both passes must agree. It records source kind,
capacity, timestamp, tool digest, and a SHA-256 digest for each byte region.
It reads only those bounded locations and does not repair media or invoke the
full campaign inspector. This diagnostic is limited to 512-byte sectors and
the campaign's 128-by-128 GPT entry layout. It preserves raw metadata even if
its checksums or geometry are invalid; parser replay decides acceptance.

Review the capture's source description and metadata against the original
observation before adding it here. Preserve the raw bytes and recorded source
kind. An image-file capture needs its original image provenance; changing its
label does not turn it into physical readback. The timestamp and description
are provenance notes, not host authentication or staging authorization, and
two matching reads do not establish an atomic device snapshot.

Copy the reviewed capture here and add a same-name expectation file using the
existing example. Record the device leg, selected disk GUID, first usable LBA,
placement, and physical-end state from the reviewed observation. Expectations
are separate from the capture tool so the parser does not define its own
expected result. The current corpus test requires an accepted v1alpha2
campaign prestate; retain a newly rejected observation for investigation
before deciding whether the campaign policy should change.

```sh
go test ./internal/provisioning/campaignmedia -run '^TestInitialGPTMetadataCapture' -count=1
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/diagnostics/gpt-capture -p 'test_*.py'
```

## Capture format

The JSON schema identifier is `kaiba-gpt-metadata-capture-v1`. It contains
`source_kind` (`image-file`, `block-device-readback`, or
`synthetic-reconstruction`), `source_description`, `captured_at` (RFC 3339),
`capture_tool_sha256`, `capacity_bytes`, `logical_sector_size_bytes`, and
ordered, nonoverlapping `regions`. Each region has an integer `offset_bytes`,
`data_base64`, and the lowercase hexadecimal `sha256` of its decoded bytes.
Reconstructed fixtures leave the capture timestamp and tool digest empty.
The test reader limits files to 128 KiB of JSON and 100 sectors of byte data.
