{ lib, pkgs }:

let
  # This exact public source archive supplies only test fixtures. No private
  # PEM bodies are stored in the repository or the check's output.
  gnutlsPublicSource = pkgs.fetchurl {
    url = "mirror://gnupg/gnutls/v3.8/gnutls-3.8.13.tar.xz";
    hash = "sha256-/+2Owb8JwkJtTxSq43feR1O1PlN9aF5gTpmosWypyX4=";
  };
  scannerTestSource = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../cmd/kaiba-public-input-key-scan
      ../internal/provisioning/pemmarkers
    ];
  };
in
pkgs.runCommand "kaiba-public-input-key-scan-source-contract"
  {
    sourceInput = scannerTestSource;
    publicSourceArchive = gnutlsPublicSource;
    nativeBuildInputs = [
      pkgs.coreutils
      pkgs.gnutar
      pkgs.go
      pkgs.xz
    ];
  }
  ''
    set -euo pipefail
    export LC_ALL=C
    export CGO_ENABLED=0
    export GOFLAGS=-buildvcs=false
    export GOCACHE="$TMPDIR/go-cache"
    export KAIBA_PEMMARKERS_PUBLIC_GNUTLS_SOURCE="$TMPDIR/crypto-selftests-pk.c"
    test "$(sha256sum "$publicSourceArchive" | cut -d ' ' -f 1)" = \
      ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e
    tar --extract --to-stdout --file "$publicSourceArchive" \
      gnutls-3.8.13/lib/crypto-selftests-pk.c > "$KAIBA_PEMMARKERS_PUBLIC_GNUTLS_SOURCE"
    test "$(sha256sum "$KAIBA_PEMMARKERS_PUBLIC_GNUTLS_SOURCE" | cut -d ' ' -f 1)" = \
      6e596be00754107fd7f7d1f132c2dc8cd0ff12bbdfc6de08c162a1dd5eedc7e8
    cp -R "$sourceInput" source
    chmod -R u+w source
    cd source
    go test ./internal/provisioning/pemmarkers ./cmd/kaiba-public-input-key-scan
    mkdir "$out"
    printf '%s\n' 'public marker source and CLI contract: pass' > "$out/result.txt"
  ''
