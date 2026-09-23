//go:build linux

package pilotenrollment

import (
	"testing"
	"testing/fstest"
)

func TestEncryptedLVMBacking(t *testing.T) {
	uuid := "11111111-1111-4111-8111-111111111111"
	makeFS := func() fstest.MapFS {
		return fstest.MapFS{"dev/block/253:0/dm/uuid": {Data: []byte("LVM-fixture")}, "dev/block/253:0/slaves/dm-1/dev": {Data: []byte("253:1\n")}, "dev/block/253:1/dm/uuid": {Data: []byte("CRYPT-LUKS2-11111111111141118111111111111111-fixture")}}
	}
	if encryptedBacking(makeFS(), "253:0", uuid) != nil {
		t.Fatal("single LVM-on-LUKS mapping rejected")
	}
	if encryptedBacking(makeFS(), "253:1", uuid) != nil {
		t.Fatal("direct LUKS mapping rejected")
	}
	for _, which := range []string{"wrong-volume", "mixed", "loop", "cycle", "missing"} {
		t.Run(which, func(t *testing.T) {
			sys := makeFS()
			switch which {
			case "wrong-volume":
				sys["dev/block/253:1/dm/uuid"] = &fstest.MapFile{Data: []byte("CRYPT-LUKS2-other-fixture")}
			case "mixed":
				sys["dev/block/253:0/slaves/other/dev"] = &fstest.MapFile{Data: []byte("8:0")}
			case "loop":
				sys["dev/block/253:0/dm/uuid"] = &fstest.MapFile{Data: []byte("loop-fixture")}
			case "cycle":
				sys["dev/block/253:0/slaves/dm-1/dev"] = &fstest.MapFile{Data: []byte("253:0")}
			case "missing":
				delete(sys, "dev/block/253:1/dm/uuid")
			}
			if encryptedBacking(sys, "253:0", uuid) == nil {
				t.Fatal("unsafe backing accepted")
			}
		})
	}
}
