//go:build linux && (amd64 || arm64)

package main

import (
	"syscall"
	"unsafe"
)

// Publish under the pinned parent without replacing any destination, including
// an empty directory created concurrently after the initial path check.
func renameDirectoryNoReplace(parent int, oldName, newName string) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(renameat2Trap, uintptr(parent), uintptr(unsafe.Pointer(oldPointer)), uintptr(parent), uintptr(unsafe.Pointer(newPointer)), 1, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
