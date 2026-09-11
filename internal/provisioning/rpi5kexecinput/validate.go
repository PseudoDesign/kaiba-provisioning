// Package rpi5kexecinput validates the Raspberry Pi 5 platform inputs that a
// stable verifier admits at the arm64 kexec handoff boundary.
package rpi5kexecinput

import (
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

const (
	MaxDeviceTreeBytes = 2 * 1024 * 1024
	// arm64's fixed COMMAND_LINE_SIZE is 2048 bytes, including the
	// terminating NUL. Keeping the textual payload at 2047 bytes or fewer
	// prevents the next kernel from silently truncating authenticated input.
	MaxCommandLineBytes = 2047

	debugConsole      = "ttyAMA10,115200n8"
	debugEarlyConsole = "pl011,0x107d001000,115200n8"
	debugUARTAlias    = "serial10"
	debugUARTAddress  = uint64(0x107d001000)
	rawPiMemoryBytes  = uint64(640 * 1024 * 1024)
)

// Validate checks a firmware-resolved Pi 5 DTB and the exact command line to
// be supplied to kexec. The development verifier deliberately fixes its UART
// to the Pi 5 debug connector; a future production policy can generalize this
// once other physical console configurations have evidence.
func Validate(deviceTreeBlob []byte, commandLine string) error {
	if len(deviceTreeBlob) == 0 || len(deviceTreeBlob) > MaxDeviceTreeBytes {
		return fmt.Errorf("device tree must contain between 1 and %d bytes", MaxDeviceTreeBytes)
	}
	tree, err := parseDeviceTree(deviceTreeBlob)
	if err != nil {
		return fmt.Errorf("device tree: %w", err)
	}
	debugPath, err := validateResolvedPi5Tree(tree)
	if err != nil {
		return fmt.Errorf("device tree: %w", err)
	}
	if err := validateKernelCommandLine(tree, debugPath, commandLine); err != nil {
		return fmt.Errorf("kernel command line: %w", err)
	}
	return nil
}

// ParseCommandLineFile accepts this spike's canonical cmdline.txt
// representation: printable ASCII arguments separated by single spaces,
// optionally followed by one LF, without quoting or escaping.
func ParseCommandLineFile(contents []byte) (string, error) {
	if len(contents) > MaxCommandLineBytes+1 {
		return "", fmt.Errorf("command-line file exceeds %d bytes plus one trailing LF", MaxCommandLineBytes)
	}
	if len(contents) > 0 && contents[len(contents)-1] == '\n' {
		contents = contents[:len(contents)-1]
	}
	commandLine := string(contents)
	if err := validateCommandLineShape(commandLine); err != nil {
		return "", err
	}
	return commandLine, nil
}

func validateResolvedPi5Tree(tree *deviceTree) (string, error) {
	compatibleValue, err := tree.property("/", "compatible")
	if err != nil {
		return "", err
	}
	compatible, err := propertyStringList(compatibleValue)
	if err != nil {
		return "", fmt.Errorf("root compatible: %w", err)
	}
	if !contains(compatible, "raspberrypi,5-model-b") || !contains(compatible, "brcm,bcm2712") {
		return "", errors.New("root compatible does not identify a Raspberry Pi 5 BCM2712")
	}
	if err := validateResolvedMemory(tree); err != nil {
		return "", err
	}

	aliasValue, err := tree.property("/aliases", debugUARTAlias)
	if err != nil {
		return "", err
	}
	debugPath, err := propertyString(aliasValue)
	if err != nil || !validNodePath(debugPath) {
		return "", fmt.Errorf("alias %s is not a canonical absolute node path", debugUARTAlias)
	}
	if err := validateEnabledPL011(tree, debugPath); err != nil {
		return "", fmt.Errorf("debug UART %q: %w", debugPath, err)
	}
	address, err := translatedRegisterAddress(tree, debugPath)
	if err != nil {
		return "", fmt.Errorf("debug UART %q: %w", debugPath, err)
	}
	if address != debugUARTAddress {
		return "", fmt.Errorf("debug UART resolves to physical address %#x, want %#x", address, debugUARTAddress)
	}

	stdoutValue, err := tree.property("/chosen", "stdout-path")
	if err != nil {
		return "", err
	}
	stdout, err := propertyString(stdoutValue)
	if err != nil {
		return "", fmt.Errorf("chosen stdout-path: %w", err)
	}
	stdoutTarget, stdoutOptions, _ := strings.Cut(stdout, ":")
	resolvedStdout, err := resolveAlias(tree, stdoutTarget)
	if err != nil {
		return "", fmt.Errorf("chosen stdout-path: %w", err)
	}
	if resolvedStdout != debugPath {
		return "", fmt.Errorf("chosen stdout-path resolves to %q, not the enabled Pi 5 debug UART %q", resolvedStdout, debugPath)
	}
	if stdoutOptions != "115200n8" {
		return "", fmt.Errorf("chosen stdout-path options are %q, want %q", stdoutOptions, "115200n8")
	}
	return debugPath, nil
}

func validateResolvedMemory(tree *deviceTree) error {
	addressCells, err := cellCount(tree, "/", "#address-cells")
	if err != nil {
		return err
	}
	sizeCells, err := cellCount(tree, "/", "#size-cells")
	if err != nil {
		return err
	}
	type memoryRegion struct {
		start uint64
		end   uint64
	}
	var regions []memoryRegion
	memoryFound := false
	nodePaths := make([]string, 0, len(tree.nodes))
	for nodePath := range tree.nodes {
		nodePaths = append(nodePaths, nodePath)
	}
	sort.Strings(nodePaths)
	for _, nodePath := range nodePaths {
		node := tree.nodes[nodePath]
		deviceTypeValue, exists := node.properties["device_type"]
		if !exists {
			continue
		}
		deviceType, err := propertyString(deviceTypeValue)
		if err != nil {
			return fmt.Errorf("memory candidate %q device_type: %w", nodePath, err)
		}
		if deviceType != "memory" {
			continue
		}
		if path.Dir(nodePath) != "/" {
			return fmt.Errorf("memory node %q is not a root child", nodePath)
		}
		memoryFound = true
		regValue, exists := node.properties["reg"]
		if !exists {
			return fmt.Errorf("memory node %q has no reg property", nodePath)
		}
		cells, err := propertyCells(regValue)
		if err != nil {
			return fmt.Errorf("memory node %q reg: %w", nodePath, err)
		}
		tupleCells := addressCells + sizeCells
		if len(cells)%tupleCells != 0 {
			return fmt.Errorf("memory node %q reg has an incomplete address/size tuple", nodePath)
		}
		for offset := 0; offset < len(cells); offset += tupleCells {
			address, _ := decodeCellValue(cells[offset : offset+addressCells])
			size, _ := decodeCellValue(cells[offset+addressCells : offset+tupleCells])
			if size == 0 {
				return fmt.Errorf("memory node %q contains a zero-size region", nodePath)
			}
			if address == 0 && size == rawPiMemoryBytes {
				return errors.New("memory describes the 640 MiB raw-DTB placeholder instead of firmware-resolved RAM")
			}
			end, ok := checkedAdd(address, size)
			if !ok {
				return fmt.Errorf("memory node %q region overflows its address", nodePath)
			}
			regions = append(regions, memoryRegion{start: address, end: end})
		}
	}
	if !memoryFound {
		return errors.New("no memory node is present")
	}
	sort.Slice(regions, func(left, right int) bool {
		if regions[left].start == regions[right].start {
			return regions[left].end < regions[right].end
		}
		return regions[left].start < regions[right].start
	})
	var total uint64
	for index, region := range regions {
		if index > 0 && region.start < regions[index-1].end {
			return fmt.Errorf(
				"memory regions [%#x,%#x) and [%#x,%#x) overlap",
				regions[index-1].start,
				regions[index-1].end,
				region.start,
				region.end,
			)
		}
		size := region.end - region.start
		var ok bool
		total, ok = checkedAdd(total, size)
		if !ok {
			return errors.New("total memory size overflows uint64")
		}
	}
	// The firmware can reserve or hide some RAM, so do not demand an exact
	// marketed capacity (including exactly 1 GiB). It must, however, replace
	// the vendor base tree's known 640 MiB placeholder with a larger physical
	// description before this tree is safe to hand to kexec.
	if total <= rawPiMemoryBytes {
		return fmt.Errorf("memory describes only %d bytes; firmware-resolved Pi 5 RAM must exceed the 640 MiB raw-DTB placeholder", total)
	}
	return nil
}

func validateEnabledPL011(tree *deviceTree, nodePath string) error {
	node, exists := tree.nodes[nodePath]
	if !exists {
		return errors.New("target node is missing")
	}
	if statusValue, exists := node.properties["status"]; exists {
		status, err := propertyString(statusValue)
		if err != nil {
			return fmt.Errorf("status: %w", err)
		}
		if status != "okay" && status != "ok" {
			return fmt.Errorf("target is not enabled (status %q)", status)
		}
	}
	compatibleValue, exists := node.properties["compatible"]
	if !exists {
		return errors.New("target has no compatible property")
	}
	compatible, err := propertyStringList(compatibleValue)
	if err != nil {
		return fmt.Errorf("compatible: %w", err)
	}
	if !contains(compatible, "arm,pl011") && !contains(compatible, "arm,pl011-axi") {
		return errors.New("target is not an ARM PL011 UART")
	}
	return nil
}

func validateKernelCommandLine(tree *deviceTree, debugPath, commandLine string) error {
	arguments, err := commandLineArguments(commandLine)
	if err != nil {
		return err
	}
	debugConsoles := 0
	earlyConsoles := 0
	for _, argument := range arguments {
		name, value, hasValue := strings.Cut(argument, "=")
		if !hasValue {
			continue
		}
		switch name {
		case "console":
			device, _, _ := strings.Cut(value, ",")
			if isFirmwareUARTAlias(device) {
				return fmt.Errorf("firmware UART alias %q is unsafe across kexec; use %s explicitly", device, debugConsole)
			}
			if aliasValue, exists := tree.optionalProperty("/aliases", device); exists {
				aliasTarget, aliasErr := propertyString(aliasValue)
				if aliasErr == nil && strings.Contains(path.Base(aliasTarget), "serial@") {
					return fmt.Errorf("device-tree UART alias %q is unsafe across kexec; use %s explicitly", device, debugConsole)
				}
			}
			if value == debugConsole {
				debugConsoles++
				continue
			}
			if strings.HasPrefix(device, "ttyAMA") || strings.HasPrefix(device, "ttyS") {
				return fmt.Errorf("serial console %q does not select the fixed Pi 5 debug UART %s", value, debugConsole)
			}
		case "earlycon":
			earlyConsoles++
			if value != debugEarlyConsole {
				return fmt.Errorf("early console %q does not select PL011 at physical address %#x", value, debugUARTAddress)
			}
		}
	}
	if debugConsoles != 1 {
		return fmt.Errorf("expected exactly one console=%s argument, found %d", debugConsole, debugConsoles)
	}
	if earlyConsoles != 1 {
		return fmt.Errorf("expected exactly one earlycon=%s argument, found %d", debugEarlyConsole, earlyConsoles)
	}
	address, err := translatedRegisterAddress(tree, debugPath)
	if err != nil {
		return fmt.Errorf("recheck debug UART address: %w", err)
	}
	if address != debugUARTAddress {
		return errors.New("early console address no longer matches the device tree debug UART")
	}
	return nil
}

func validateCommandLineShape(commandLine string) error {
	_, err := commandLineArguments(commandLine)
	return err
}

// commandLineArguments intentionally accepts a narrower grammar than Linux's
// next_arg parser. Linux gives double quotes token-boundary semantics, while
// strings.Fields treats them as ordinary bytes and recognizes non-ASCII
// whitespace that Linux does not. For this fixed Pi spike, requiring canonical
// printable-ASCII tokens makes the validated boundaries exactly the boundaries
// the kernel will consume without duplicating the kernel's permissive parser.
func commandLineArguments(commandLine string) ([]string, error) {
	if commandLine == "" || len(commandLine) > MaxCommandLineBytes {
		return nil, fmt.Errorf("must contain between 1 and %d bytes", MaxCommandLineBytes)
	}
	if strings.ContainsAny(commandLine, "\x00\r\n") {
		return nil, errors.New("must not contain NUL or line breaks")
	}
	if strings.Contains(commandLine, "\"") {
		return nil, errors.New("must not contain double quotes; quoted arguments are unsupported")
	}
	if strings.Contains(commandLine, "\\") {
		return nil, errors.New("must not contain backslash escapes")
	}
	if commandLine[0] == ' ' || commandLine[len(commandLine)-1] == ' ' || strings.Contains(commandLine, "  ") {
		return nil, errors.New("arguments must be separated by exactly one ASCII space, without leading or trailing spaces")
	}
	for index := 0; index < len(commandLine); index++ {
		value := commandLine[index]
		if value != ' ' && (value < '!' || value > '~') {
			return nil, errors.New("must contain only printable ASCII arguments and ASCII-space separators")
		}
	}
	arguments := strings.Split(commandLine, " ")
	for _, argument := range arguments {
		if argument == "--" {
			return nil, errors.New("must not contain the kernel argument terminator --")
		}
	}
	return arguments, nil
}

func translatedRegisterAddress(tree *deviceTree, nodePath string) (uint64, error) {
	parent := path.Dir(nodePath)
	if parent == "." || parent == nodePath {
		return 0, errors.New("register node has no parent bus")
	}
	addressCells, err := cellCount(tree, parent, "#address-cells")
	if err != nil {
		return 0, err
	}
	sizeCells, err := cellCount(tree, parent, "#size-cells")
	if err != nil {
		return 0, err
	}
	reg, err := tree.property(nodePath, "reg")
	if err != nil {
		return 0, err
	}
	cells, err := propertyCells(reg)
	if err != nil {
		return 0, fmt.Errorf("reg: %w", err)
	}
	tupleCells := addressCells + sizeCells
	if len(cells) < tupleCells || len(cells)%tupleCells != 0 {
		return 0, errors.New("reg has an incomplete address/size tuple")
	}
	address, _ := decodeCellValue(cells[:addressCells])
	registerSize, _ := decodeCellValue(cells[addressCells:tupleCells])
	if registerSize == 0 {
		return 0, errors.New("reg has a zero-size region")
	}

	for parent != "/" {
		grandparent := path.Dir(parent)
		childAddressCells, err := cellCount(tree, parent, "#address-cells")
		if err != nil {
			return 0, err
		}
		parentAddressCells, err := cellCount(tree, grandparent, "#address-cells")
		if err != nil {
			return 0, err
		}
		rangeSizeCells, err := cellCount(tree, parent, "#size-cells")
		if err != nil {
			return 0, err
		}
		ranges, exists := tree.optionalProperty(parent, "ranges")
		if !exists {
			return 0, fmt.Errorf("bus %q has no ranges property", parent)
		}
		if len(ranges) == 0 {
			parent = grandparent
			continue
		}
		rangeCells, err := propertyCells(ranges)
		if err != nil {
			return 0, fmt.Errorf("bus %q ranges: %w", parent, err)
		}
		rangeTupleCells := childAddressCells + parentAddressCells + rangeSizeCells
		if len(rangeCells)%rangeTupleCells != 0 {
			return 0, fmt.Errorf("bus %q ranges has an incomplete tuple", parent)
		}
		translated := false
		for offset := 0; offset < len(rangeCells); offset += rangeTupleCells {
			childBase, _ := decodeCellValue(rangeCells[offset : offset+childAddressCells])
			parentBaseOffset := offset + childAddressCells
			parentBase, _ := decodeCellValue(rangeCells[parentBaseOffset : parentBaseOffset+parentAddressCells])
			rangeSize, _ := decodeCellValue(rangeCells[parentBaseOffset+parentAddressCells : offset+rangeTupleCells])
			childEnd, childOK := checkedAdd(childBase, rangeSize)
			registerEnd, registerOK := checkedAdd(address, registerSize)
			if !childOK || !registerOK || address < childBase || registerEnd > childEnd {
				continue
			}
			delta := address - childBase
			address, translated = checkedAdd(parentBase, delta)
			if !translated {
				return 0, fmt.Errorf("bus %q translated address overflows", parent)
			}
			break
		}
		if !translated {
			return 0, fmt.Errorf("bus %q has no range containing register %#x", parent, address)
		}
		parent = grandparent
	}
	return address, nil
}

func resolveAlias(tree *deviceTree, target string) (string, error) {
	if validNodePath(target) {
		if _, exists := tree.nodes[target]; !exists {
			return "", fmt.Errorf("target node %q is missing", target)
		}
		return target, nil
	}
	if target == "" || strings.Contains(target, "/") {
		return "", fmt.Errorf("target %q is neither an alias nor an absolute node path", target)
	}
	value, err := tree.property("/aliases", target)
	if err != nil {
		return "", err
	}
	resolved, err := propertyString(value)
	if err != nil || !validNodePath(resolved) {
		return "", fmt.Errorf("alias %q does not contain a canonical absolute node path", target)
	}
	if _, exists := tree.nodes[resolved]; !exists {
		return "", fmt.Errorf("alias %q targets missing node %q", target, resolved)
	}
	return resolved, nil
}

func validNodePath(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && path.Clean(value) == value
}

func isFirmwareUARTAlias(value string) bool {
	for _, prefix := range []string{"serial", "uart"} {
		if strings.HasPrefix(value, prefix) && allDecimal(value[len(prefix):]) {
			return true
		}
	}
	return false
}

func allDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
