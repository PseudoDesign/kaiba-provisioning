{ lib }:
value:
let
  path = toString value;
  matched = builtins.match "(/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+)(/.*)?" path;
in
assert lib.assertMsg (matched != null) "staging input must name an immutable store object";
# Imported public paths can arrive as plain strings. Retain an explicit reference
# to their registered store root, including when the selected file is a subpath.
# Derivation contexts already express how to realize that root and stay intact.
if builtins.hasContext path then
  path
else
  builtins.appendContext path {
    "${builtins.head matched}" = {
      path = true;
    };
  }
