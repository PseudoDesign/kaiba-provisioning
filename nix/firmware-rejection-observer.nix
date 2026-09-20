{ pkgs }:
let
  source = ../tools/firmware-rejection-observer;
  bpf =
    pkgs.runCommand "kaiba-firmware-rejection-observer-bpf"
      {
        nativeBuildInputs = [ pkgs.llvmPackages.clang-unwrapped ];
      }
      ''
        mkdir -p "$out"
        clang -target bpf -O2 -g -Wall -Wextra -Werror \
          -I${pkgs.linuxHeaders}/include -I${pkgs.libbpf}/include -I${source} \
          -c ${source}/observer.bpf.c -o "$out/observer.bpf.o"
      '';
  package = pkgs.stdenv.mkDerivation {
    pname = "kaiba-firmware-rejection-observer";
    version = "0.1.0";
    src = source;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = with pkgs; [
      libbpf
      elfutils
      zlib
      (zstd.override { enableStatic = true; })
      glibc.static
    ];
    buildPhase = ''
      $CC -std=c11 -Wall -Wextra -Werror -O2 -static \
        $(pkg-config --cflags libbpf) main.c $(pkg-config --libs --static libbpf) \
        -o kaiba-firmware-rejection-observer
    '';
    installPhase = ''
      install -Dm0555 kaiba-firmware-rejection-observer "$out/bin/kaiba-firmware-rejection-observer"
      install -Dm0444 ${bpf}/observer.bpf.o "$out/lib/observer.bpf.o"
    '';
  };
  check =
    pkgs.runCommand "kaiba-firmware-rejection-observer-check"
      {
        nativeBuildInputs = [
          pkgs.stdenv.cc
          pkgs.binutils
          pkgs.python3
        ];
      }
      ''
        $CC -std=c11 -Wall -Wextra -Werror -O2 -I${source} \
          ${../tests/firmware-rejection-observer/classify.c} -o classify
        ./classify
        $CC -std=c11 -Wall -Wextra -Werror -O2 -I${source} -I${pkgs.libbpf}/include \
          ${source}/main.c ${../tests/firmware-rejection-observer/loader-fixture.c} -o loader-fixture
        python3 -B ${../tests/firmware-rejection-observer/test_loader.py} ./loader-fixture
        readelf -l ${package}/bin/kaiba-firmware-rejection-observer > segments
        ! grep -q INTERP segments
        test -s ${package}/lib/observer.bpf.o
        mkdir -p "$out"
        cp classify segments "$out/"
      '';
in
{
  inherit package check;
}
