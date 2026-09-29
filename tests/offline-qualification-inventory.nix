{ pkgs }:
pkgs.runCommand "kaiba-offline-qualification-inventory-check"
  {
    nativeBuildInputs = [ pkgs.python3 ];
    KAIBA_OFFLINE_INVENTORY = ../scripts/offline-qualification/inventory.py;
    KAIBA_REBOOT_OBSERVER = ../scripts/offline-qualification/observe_reboot.py;
  }
  ''
    python3 -B ${./offline-qualification/test_inventory.py}
    python3 -B ${./offline-qualification/test_observe_reboot.py}
    touch "$out"
  ''
