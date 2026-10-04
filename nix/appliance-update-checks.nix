{ pkgs, lib }:
let
  source = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../internal/appliancewire
      ../internal/appliancestate
      ../internal/provisioning/appliance
      ../tools/check-appliance-wire.py
    ];
  };
in
pkgs.runCommand "kaiba-appliance-update-checks"
  {
    src = source;
    nativeBuildInputs = [
      pkgs.go
      pkgs.stdenv.cc
      pkgs.python3
    ];
  }
  ''
    cp -r "$src" source
    chmod -R u+w source
    cd source
    export GOCACHE="$TMPDIR/go-cache" GOPATH="$TMPDIR/go-path"
    export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
    python3 -B tools/check-appliance-wire.py
    go test -race ./internal/appliancewire ./internal/appliancestate ./internal/provisioning/appliance
    mkdir -p "$out"
    cat > "$out/report.json" <<'JSON'
    {"assurance":"native-software-tests-with-disposable-keys-and-regular-files","software_checks_passed":true,"native_selector_qualified":false,"physical_execution_authorized":false,"physical_staging_performed":false,"production_ready":false}
    JSON
  ''
