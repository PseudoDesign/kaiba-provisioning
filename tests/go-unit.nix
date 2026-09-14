{
  pkgs,
  lib,
  source,
  name ? "kaiba-go-unit-tests",
  packages ? [ "./..." ],
  static ? false,
}:

# Keep test execution independent of probe firmware and application link steps.
# The static contract suite also supplies the publication consumed by the Nix
# schema check, avoiding another compile/test invocation just to make that file.
pkgs.runCommand name
  {
    nativeBuildInputs = [ pkgs.go ] ++ lib.optionals (!static) [ pkgs.stdenv.cc ];
    CGO_ENABLED = if static then "0" else "1";
  }
  ''
    set -euo pipefail
    export GOCACHE="$TMPDIR/go-cache"
    export GOPATH="$TMPDIR/go-path"
    export LC_ALL=C
    ${lib.optionalString static ''
      export KAIBA_SIGNED_RELEASE_TEST_PUBLICATION="$TMPDIR/publication.json"
    ''}
    cd ${source}
    mkdir -p "$out"
    go test ${lib.escapeShellArgs packages} | tee "$out/test-results.txt"
    ${lib.optionalString static ''
      test -s "$TMPDIR/publication.json"
      install -m 0444 "$TMPDIR/publication.json" "$out/publication.json"
    ''}
    touch "$out/passed"
  ''
