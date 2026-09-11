package rpi5kexecinput

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	fdtMagic     = 0xd00dfeed
	fdtHeaderLen = 40
	fdtVersion   = 17

	fdtBeginNode = 1
	fdtEndNode   = 2
	fdtProperty  = 3
	fdtNop       = 4
	fdtEnd       = 9
)

type deviceTree struct {
	nodes map[string]deviceTreeNode
}

type deviceTreeNode struct {
	properties map[string][]byte
}

func parseDeviceTree(blob []byte) (*deviceTree, error) {
	if len(blob) < fdtHeaderLen {
		return nil, errors.New("header is truncated")
	}
	word := func(offset int) uint32 {
		return binary.BigEndian.Uint32(blob[offset : offset+4])
	}
	if word(0) != fdtMagic {
		return nil, errors.New("magic is invalid")
	}
	totalSize := uint64(word(4))
	structureOffset := uint64(word(8))
	stringsOffset := uint64(word(12))
	reservationOffset := uint64(word(16))
	version := word(20)
	lastCompatibleVersion := word(24)
	stringsSize := uint64(word(32))
	structureSize := uint64(word(36))
	if totalSize != uint64(len(blob)) {
		return nil, fmt.Errorf("declared size %d does not equal file size %d", totalSize, len(blob))
	}
	if version != fdtVersion || lastCompatibleVersion > fdtVersion {
		return nil, fmt.Errorf("unsupported format version %d (last compatible %d)", version, lastCompatibleVersion)
	}
	if reservationOffset < fdtHeaderLen || reservationOffset%8 != 0 {
		return nil, errors.New("memory reservation block offset is invalid")
	}
	if structureOffset%4 != 0 || structureSize == 0 || structureSize%4 != 0 {
		return nil, errors.New("structure block location is invalid")
	}
	if stringsSize == 0 {
		return nil, errors.New("strings block is empty")
	}
	structureEnd, ok := checkedRegionEnd(structureOffset, structureSize, totalSize)
	if !ok {
		return nil, errors.New("structure block exceeds the declared device tree")
	}
	stringsEnd, ok := checkedRegionEnd(stringsOffset, stringsSize, totalSize)
	if !ok {
		return nil, errors.New("strings block exceeds the declared device tree")
	}
	// Firmware-produced Pi trees use the canonical reservation, structure,
	// strings ordering. Requiring it removes overlap and parser ambiguity at
	// this security boundary.
	if reservationOffset >= structureOffset || structureEnd > stringsOffset || stringsEnd != totalSize {
		return nil, errors.New("device tree blocks are overlapping or non-canonical")
	}
	if err := validateReservationBlock(blob[reservationOffset:structureOffset]); err != nil {
		return nil, err
	}

	structure := blob[structureOffset:structureEnd]
	stringTable := blob[stringsOffset:stringsEnd]
	tree := &deviceTree{nodes: make(map[string]deviceTreeNode)}
	var stack []string
	rootSeen := false
	rootClosed := false
	for cursor := 0; cursor < len(structure); {
		if cursor+4 > len(structure) {
			return nil, errors.New("structure token is truncated")
		}
		token := binary.BigEndian.Uint32(structure[cursor : cursor+4])
		cursor += 4
		switch token {
		case fdtBeginNode:
			if rootClosed {
				return nil, errors.New("node appears after the root node was closed")
			}
			end := indexByte(structure, cursor, 0)
			if end < 0 {
				return nil, errors.New("node name is not terminated")
			}
			name := string(structure[cursor:end])
			cursor = align4(end + 1)
			if cursor > len(structure) {
				return nil, errors.New("node name padding exceeds the structure block")
			}
			var path string
			if len(stack) == 0 {
				if rootSeen || name != "" {
					return nil, errors.New("root node is invalid")
				}
				rootSeen = true
				path = "/"
			} else {
				if name == "" || strings.Contains(name, "/") {
					return nil, errors.New("child node name is invalid")
				}
				parent := stack[len(stack)-1]
				if parent == "/" {
					path = "/" + name
				} else {
					path = parent + "/" + name
				}
			}
			if _, exists := tree.nodes[path]; exists {
				return nil, fmt.Errorf("duplicate node %q", path)
			}
			tree.nodes[path] = deviceTreeNode{properties: make(map[string][]byte)}
			stack = append(stack, path)
		case fdtEndNode:
			if len(stack) == 0 {
				return nil, errors.New("unmatched end-node token")
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				rootClosed = true
			}
		case fdtProperty:
			if len(stack) == 0 || cursor+8 > len(structure) {
				return nil, errors.New("property header is misplaced or truncated")
			}
			length := uint64(binary.BigEndian.Uint32(structure[cursor : cursor+4]))
			nameOffset := uint64(binary.BigEndian.Uint32(structure[cursor+4 : cursor+8]))
			cursor += 8
			valueEnd, ok := checkedRegionEnd(uint64(cursor), length, uint64(len(structure)))
			if !ok {
				return nil, errors.New("property value exceeds the structure block")
			}
			name, err := tableString(stringTable, nameOffset)
			if err != nil {
				return nil, err
			}
			if name == "" || strings.ContainsRune(name, '/') {
				return nil, errors.New("property name is invalid")
			}
			path := stack[len(stack)-1]
			node := tree.nodes[path]
			if _, exists := node.properties[name]; exists {
				return nil, fmt.Errorf("duplicate property %q on node %q", name, path)
			}
			node.properties[name] = blobSlice(structure[cursor:int(valueEnd)])
			tree.nodes[path] = node
			cursor = align4(int(valueEnd))
			if cursor > len(structure) {
				return nil, errors.New("property padding exceeds the structure block")
			}
		case fdtNop:
			if !rootSeen || rootClosed {
				return nil, errors.New("NOP token appears outside the root node")
			}
		case fdtEnd:
			if !rootSeen || !rootClosed || len(stack) != 0 {
				return nil, errors.New("device tree ended before closing the root node")
			}
			for _, trailing := range structure[cursor:] {
				if trailing != 0 {
					return nil, errors.New("non-zero bytes follow the end token")
				}
			}
			return tree, nil
		default:
			return nil, fmt.Errorf("unknown structure token %#x", token)
		}
	}
	return nil, errors.New("structure block has no end token")
}

func validateReservationBlock(block []byte) error {
	if len(block) < 16 || len(block)%8 != 0 {
		return errors.New("memory reservation block is truncated")
	}
	for offset := 0; offset+16 <= len(block); offset += 16 {
		address := binary.BigEndian.Uint64(block[offset : offset+8])
		size := binary.BigEndian.Uint64(block[offset+8 : offset+16])
		if address == 0 && size == 0 {
			return nil
		}
	}
	return errors.New("memory reservation block has no terminator")
}

func (tree *deviceTree) property(path, name string) ([]byte, error) {
	node, ok := tree.nodes[path]
	if !ok {
		return nil, fmt.Errorf("required node %q is missing", path)
	}
	value, ok := node.properties[name]
	if !ok {
		return nil, fmt.Errorf("required property %q on node %q is missing", name, path)
	}
	return value, nil
}

func (tree *deviceTree) optionalProperty(path, name string) ([]byte, bool) {
	node, ok := tree.nodes[path]
	if !ok {
		return nil, false
	}
	value, ok := node.properties[name]
	return value, ok
}

func propertyString(value []byte) (string, error) {
	if len(value) < 2 || value[len(value)-1] != 0 || indexByte(value, 0, 0) != len(value)-1 {
		return "", errors.New("property is not one canonical string")
	}
	return string(value[:len(value)-1]), nil
}

func propertyStringList(value []byte) ([]string, error) {
	if len(value) < 2 || value[len(value)-1] != 0 {
		return nil, errors.New("property is not a terminated string list")
	}
	parts := strings.Split(string(value[:len(value)-1]), "\x00")
	for _, part := range parts {
		if part == "" {
			return nil, errors.New("property contains an empty string-list item")
		}
	}
	return parts, nil
}

func propertyCells(value []byte) ([]uint32, error) {
	if len(value) == 0 || len(value)%4 != 0 {
		return nil, errors.New("property is not a non-empty cell array")
	}
	cells := make([]uint32, len(value)/4)
	for index := range cells {
		cells[index] = binary.BigEndian.Uint32(value[index*4 : index*4+4])
	}
	return cells, nil
}

func cellCount(tree *deviceTree, path, property string) (int, error) {
	value, err := tree.property(path, property)
	if err != nil {
		return 0, err
	}
	if len(value) != 4 {
		return 0, fmt.Errorf("property %q on node %q is not one cell", property, path)
	}
	count := binary.BigEndian.Uint32(value)
	if count < 1 || count > 2 {
		return 0, fmt.Errorf("property %q on node %q has unsupported value %d", property, path, count)
	}
	return int(count), nil
}

func decodeCellValue(cells []uint32) (uint64, error) {
	if len(cells) < 1 || len(cells) > 2 {
		return 0, errors.New("only one- or two-cell integer values are supported")
	}
	var value uint64
	for _, cell := range cells {
		value = value<<32 | uint64(cell)
	}
	return value, nil
}

func checkedRegionEnd(offset, size, limit uint64) (uint64, bool) {
	if offset > limit || size > limit-offset {
		return 0, false
	}
	return offset + size, true
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if right > math.MaxUint64-left {
		return 0, false
	}
	return left + right, true
}

func tableString(table []byte, offset uint64) (string, error) {
	if offset >= uint64(len(table)) {
		return "", errors.New("property name offset exceeds the strings block")
	}
	end := indexByte(table, int(offset), 0)
	if end < 0 {
		return "", errors.New("property name is not terminated in the strings block")
	}
	return string(table[int(offset):end]), nil
}

func indexByte(value []byte, start int, target byte) int {
	for index := start; index < len(value); index++ {
		if value[index] == target {
			return index
		}
	}
	return -1
}

func align4(value int) int {
	return (value + 3) &^ 3
}

func blobSlice(value []byte) []byte {
	return append([]byte(nil), value...)
}
