{ lib, image }:
image.overrideAttrs (
  old:
  let
    mkfs = "fakeroot mkfs.ext4";
    # This is filesystem layout metadata, not a cryptographic secret.
    hashSeed = "4b414942-4152-4f4f-9400-000000000002";
  in
  assert lib.assertMsg (
    builtins.length (lib.splitString mkfs old.buildCommand) == 2
  ) "the pinned ext4 builder changed; review its reproducibility before building images";
  {
    # The upstream builder fixes the mkfs clock and filesystem UUID, but
    # leaves the directory hash seed random and runs resize2fs outside
    # faketime. Both change image bytes when a missing output is rebuilt.
    buildCommand = ''
      export E2FSPROGS_FAKE_TIME=1
      export LC_ALL=C
      export TZ=UTC
    ''
    + lib.replaceStrings [ mkfs ] [ "${mkfs} -E hash_seed=${hashSeed}" ] old.buildCommand;
  }
)
