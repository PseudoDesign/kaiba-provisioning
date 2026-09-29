{ pkgs }:
pkgs.runCommand "kaiba-offline-qualification-inventory-check"
  {
    nativeBuildInputs = [ pkgs.python3 ];
    KAIBA_OFFLINE_INVENTORY = ../scripts/offline-qualification/inventory.py;
  }
  ''
    python3 -B ${./offline-qualification/test_inventory.py}
    touch "$out"
  ''
