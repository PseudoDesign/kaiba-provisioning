package rpi5kexecinput

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

const validCommandLine = "console=ttyAMA10,115200n8 console=tty1 earlycon=pl011,0x107d001000,115200n8 root=fstab"

// retainedPhysicalCommandLine is the exact second-stage command line retained
// as evidence during the 2026-09-10 physical Pi 5 diagnostic.
const retainedPhysicalCommandLine = "console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8 ignore_loglevel keep_bootcon loglevel=8 initcall_debug nokaslr rdinit=/init kaiba.self_kexec_beacon=1"

func TestValidateAcceptsResolvedPi5DebugUARTInputs(t *testing.T) {
	if err := Validate(buildTestDeviceTree(defaultTreeOptions()), validCommandLine); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := Validate(buildTestDeviceTree(defaultTreeOptions()), retainedPhysicalCommandLine); err != nil {
		t.Fatalf("Validate retained physical command line: %v", err)
	}

	absoluteStdout := defaultTreeOptions()
	absoluteStdout.stdoutPath = testDebugUARTPath + ":115200n8"
	if err := Validate(buildTestDeviceTree(absoluteStdout), validCommandLine); err != nil {
		t.Fatalf("Validate with absolute stdout-path: %v", err)
	}

	multipleBanks := defaultTreeOptions()
	multipleBanks.memoryRegions = []testMemoryRegion{
		{address: 0, size: 512 * 1024 * 1024},
		{address: 512 * 1024 * 1024, size: 512 * 1024 * 1024},
	}
	if err := Validate(buildTestDeviceTree(multipleBanks), validCommandLine); err != nil {
		t.Fatalf("Validate with multiple memory regions: %v", err)
	}

	firmwareReservedOneGiB := defaultTreeOptions()
	firmwareReservedOneGiB.memoryRegions = []testMemoryRegion{{address: 0, size: 0x3fc00000}}
	if err := Validate(buildTestDeviceTree(firmwareReservedOneGiB), validCommandLine); err != nil {
		t.Fatalf("Validate with firmware-reserved 1 GiB memory: %v", err)
	}

	missingStatus := defaultTreeOptions()
	missingStatus.omitDebugStatus = true // A missing DT status means enabled.
	if err := Validate(buildTestDeviceTree(missingStatus), validCommandLine); err != nil {
		t.Fatalf("Validate with implicit okay status: %v", err)
	}
}

func TestValidateRejectsFirmwareConsoleAliasesAndAmbiguousSerialConsoles(t *testing.T) {
	withDeviceTreeAlias := defaultTreeOptions()
	withDeviceTreeAlias.extraAliases = []testProperty{{"debug-uart", stringProperty(testDebugUARTPath)}}
	for _, test := range []struct {
		name        string
		options     testTreeOptions
		commandLine string
		want        string
	}{
		{"serial0", defaultTreeOptions(), replaceConsole("console=serial0,115200n8"), "firmware UART alias \"serial0\""},
		{"serial1", defaultTreeOptions(), replaceConsole("console=serial1,115200n8"), "firmware UART alias \"serial1\""},
		{"serial10", defaultTreeOptions(), replaceConsole("console=serial10,115200n8"), "firmware UART alias \"serial10\""},
		{"uart0", defaultTreeOptions(), replaceConsole("console=uart0,115200n8"), "firmware UART alias \"uart0\""},
		{"device tree alias", withDeviceTreeAlias, replaceConsole("console=debug-uart,115200n8"), "device-tree UART alias \"debug-uart\""},
		{"wrong PL011", defaultTreeOptions(), replaceConsole("console=ttyAMA0,115200n8"), "does not select the fixed Pi 5 debug UART"},
		{"wrong 8250 UART", defaultTreeOptions(), replaceConsole("console=ttyS0,115200n8"), "does not select the fixed Pi 5 debug UART"},
		{"wrong baud", defaultTreeOptions(), replaceConsole("console=ttyAMA10,9600n8"), "does not select the fixed Pi 5 debug UART"},
		{"missing debug console", defaultTreeOptions(), strings.Replace(validCommandLine, "console=ttyAMA10,115200n8 ", "", 1), "expected exactly one console=ttyAMA10,115200n8"},
		{"duplicate debug console", defaultTreeOptions(), validCommandLine + " console=ttyAMA10,115200n8", "found 2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := Validate(buildTestDeviceTree(test.options), test.commandLine)
			assertErrorContains(t, err, test.want)
		})
	}
}

func TestValidateRequiresPhysicalPi5EarlyConsole(t *testing.T) {
	for _, test := range []struct {
		name        string
		commandLine string
		want        string
	}{
		{"missing", strings.Replace(validCommandLine, " earlycon=pl011,0x107d001000,115200n8", "", 1), "expected exactly one earlycon="},
		{"wrong address", strings.Replace(validCommandLine, "0x107d001000", "0x7d001000", 1), "does not select PL011 at physical address 0x107d001000"},
		{"wrong driver", strings.Replace(validCommandLine, "earlycon=pl011", "earlycon=uart8250", 1), "does not select PL011"},
		{"duplicate", validCommandLine + " earlycon=pl011,0x107d001000,115200n8", "found 2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertErrorContains(t, Validate(buildTestDeviceTree(defaultTreeOptions()), test.commandLine), test.want)
		})
	}
}

func TestValidateRejectsAmbiguousCommandLineTokenization(t *testing.T) {
	for _, test := range []struct {
		name        string
		commandLine string
		want        string
	}{
		{
			"matched quote swallows required arguments",
			`root="fstab console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8 ignored"`,
			"double quotes",
		},
		{
			"open quote swallows required arguments",
			`root="fstab console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8`,
			"double quotes",
		},
		{
			"non-breaking space hides console from Linux",
			"root=fstab\u00a0console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8",
			"printable ASCII",
		},
		{
			"horizontal tab separators",
			strings.ReplaceAll(validCommandLine, " ", "\t"),
			"printable ASCII",
		},
		{
			"vertical tab separator",
			strings.Replace(validCommandLine, " ", "\v", 1),
			"printable ASCII",
		},
		{
			"form feed separator",
			strings.Replace(validCommandLine, " ", "\f", 1),
			"printable ASCII",
		},
		{
			"leading space",
			" " + validCommandLine,
			"exactly one ASCII space",
		},
		{
			"trailing space",
			validCommandLine + " ",
			"exactly one ASCII space",
		},
		{
			"repeated space",
			strings.Replace(validCommandLine, " ", "  ", 1),
			"exactly one ASCII space",
		},
		{
			"backslash escape",
			strings.Replace(validCommandLine, " ", `\ `, 1),
			"backslash escapes",
		},
		{
			"kernel argument terminator hides required arguments",
			"root=fstab -- console=ttyAMA10,115200n8 earlycon=pl011,0x107d001000,115200n8",
			"argument terminator",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertErrorContains(
				t,
				Validate(buildTestDeviceTree(defaultTreeOptions()), test.commandLine),
				test.want,
			)
		})
	}
}

func TestValidateEnforcesArm64CommandLineBufferBoundary(t *testing.T) {
	atLimit := commandLineWithRequiredUARTSuffix(t, MaxCommandLineBytes)
	if err := Validate(buildTestDeviceTree(defaultTreeOptions()), atLimit); err != nil {
		t.Fatalf("Validate command line at arm64 limit: %v", err)
	}

	// The pinned arm64 kernel copies at most COMMAND_LINE_SIZE-1 bytes from
	// /chosen/bootargs. This vector would previously validate even though both
	// required UART arguments occur after that truncation boundary.
	truncationVector := strings.Repeat("x", MaxCommandLineBytes) + " " + validCommandLine
	assertErrorContains(
		t,
		Validate(buildTestDeviceTree(defaultTreeOptions()), truncationVector),
		"between 1 and 2047 bytes",
	)

	overLimit := commandLineWithRequiredUARTSuffix(t, MaxCommandLineBytes+1)
	assertErrorContains(
		t,
		Validate(buildTestDeviceTree(defaultTreeOptions()), overLimit),
		"between 1 and 2047 bytes",
	)
}

func TestValidateRejectsRawOrUnresolvedPi5Memory(t *testing.T) {
	for _, test := range []struct {
		name    string
		regions []testMemoryRegion
		omit    bool
		want    string
	}{
		{
			"known raw placeholder",
			[]testMemoryRegion{{address: 0, size: 640 * 1024 * 1024}},
			false,
			"640 MiB raw-DTB placeholder",
		},
		{"undersized", []testMemoryRegion{{address: 0, size: 512 * 1024 * 1024}}, false, "must exceed the 640 MiB"},
		{
			"zero region",
			[]testMemoryRegion{{address: 0, size: 0}},
			false,
			"zero-size region",
		},
		{"missing", nil, true, "no memory node is present"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := defaultTreeOptions()
			options.memoryRegions = test.regions
			options.omitMemory = test.omit
			assertErrorContains(t, Validate(buildTestDeviceTree(options), validCommandLine), test.want)
		})
	}
}

func TestValidateRejectsOverlappingResolvedMemoryRegions(t *testing.T) {
	for _, test := range []struct {
		name    string
		regions []testMemoryRegion
	}{
		{
			"duplicate",
			[]testMemoryRegion{
				{address: 0, size: 512 * 1024 * 1024},
				{address: 0, size: 512 * 1024 * 1024},
			},
		},
		{
			"partial",
			[]testMemoryRegion{
				{address: 0, size: 512 * 1024 * 1024},
				{address: 256 * 1024 * 1024, size: 512 * 1024 * 1024},
			},
		},
		{
			"nested",
			[]testMemoryRegion{
				{address: 0, size: 768 * 1024 * 1024},
				{address: 256 * 1024 * 1024, size: 256 * 1024 * 1024},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := defaultTreeOptions()
			options.memoryRegions = test.regions
			assertErrorContains(
				t,
				Validate(buildTestDeviceTree(options), validCommandLine),
				"memory regions",
			)
		})
	}
}

func TestValidateRejectsObservedCampaignShapeAtBothBoundaries(t *testing.T) {
	// These are the salient bytes observed in the physical campaign: the
	// build-time DTB retained memory@0=<0 0 0 0x28000000>, while firmware only
	// rewrote console=serial0 to ttyAMA10 during the first (non-kexec) boot.
	observed := defaultTreeOptions()
	observed.memoryRegions = []testMemoryRegion{{address: 0, size: 0x28000000}}
	observedCommandLine := "console=serial0,115200n8 console=tty1 console=serial0,115200 root=fstab"
	assertErrorContains(
		t,
		Validate(buildTestDeviceTree(observed), observedCommandLine),
		"640 MiB raw-DTB placeholder",
	)

	// Once the tree has a plausible firmware-resolved memory size, the same
	// delegated command line must still fail: kexec never reruns the firmware
	// alias substitution on which serial0 depends.
	observed.memoryRegions = []testMemoryRegion{{address: 0, size: 0x3fc00000}}
	assertErrorContains(
		t,
		Validate(buildTestDeviceTree(observed), observedCommandLine),
		"firmware UART alias \"serial0\"",
	)
}

func TestValidateRejectsWrongOrUnusablePi5DebugUART(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testTreeOptions)
		want   string
	}{
		{"missing serial10 alias", func(o *testTreeOptions) { o.omitDebugAlias = true }, "property \"serial10\""},
		{"missing alias target", func(o *testTreeOptions) { o.debugAlias = "/missing/serial@7d001000" }, "target node is missing"},
		{"disabled", func(o *testTreeOptions) { o.debugStatus = "disabled" }, "target is not enabled"},
		{"wrong UART type", func(o *testTreeOptions) { o.debugCompatible = []string{"ns16550a"} }, "not an ARM PL011"},
		{"wrong register", func(o *testTreeOptions) { o.debugRegister = 0x7d002000 }, "resolves to physical address 0x107d002000"},
		{"wrong bus mapping", func(o *testTreeOptions) { o.socParentBase = 0x20_00000000 }, "resolves to physical address 0x207d001000"},
		{"chosen wrong alias", func(o *testTreeOptions) { o.stdoutPath = "serial0:115200n8" }, "not the enabled Pi 5 debug UART"},
		{"chosen wrong options", func(o *testTreeOptions) { o.stdoutPath = "serial10:9600n8" }, "options are \"9600n8\""},
		{"chosen missing options", func(o *testTreeOptions) { o.stdoutPath = "serial10" }, "options are \"\""},
		{"missing stdout", func(o *testTreeOptions) { o.omitStdout = true }, "property \"stdout-path\""},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := defaultTreeOptions()
			test.mutate(&options)
			assertErrorContains(t, Validate(buildTestDeviceTree(options), validCommandLine), test.want)
		})
	}
}

func TestValidateRejectsNonPi5AndMalformedDeviceTrees(t *testing.T) {
	notPi := defaultTreeOptions()
	notPi.rootCompatible = []string{"raspberrypi,4-model-b", "brcm,bcm2711"}
	assertErrorContains(t, Validate(buildTestDeviceTree(notPi), validCommandLine), "does not identify a Raspberry Pi 5")

	valid := buildTestDeviceTree(defaultTreeOptions())
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
		want   string
	}{
		{"empty", func([]byte) []byte { return nil }, "device tree must contain"},
		{"truncated header", func([]byte) []byte { return []byte{0xd0, 0x0d} }, "header is truncated"},
		{"bad magic", func(value []byte) []byte { value[0] = 0; return value }, "magic is invalid"},
		{"size mismatch", func(value []byte) []byte { return value[:len(value)-1] }, "does not equal file size"},
		{"unsupported version", func(value []byte) []byte { binary.BigEndian.PutUint32(value[20:24], 16); return value }, "unsupported format version"},
		{"bad property name offset", func(value []byte) []byte {
			structureOffset := int(binary.BigEndian.Uint32(value[8:12]))
			// Root BEGIN_NODE (8 bytes), then the first property token,
			// length, and name offset.
			binary.BigEndian.PutUint32(value[structureOffset+16:structureOffset+20], ^uint32(0))
			return value
		}, "property name offset exceeds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := test.mutate(append([]byte(nil), valid...))
			assertErrorContains(t, Validate(candidate, validCommandLine), test.want)
		})
	}
}

func TestParseCommandLineFile(t *testing.T) {
	for _, contents := range [][]byte{[]byte(validCommandLine), []byte(validCommandLine + "\n")} {
		got, err := ParseCommandLineFile(contents)
		if err != nil {
			t.Fatalf("ParseCommandLineFile: %v", err)
		}
		if got != validCommandLine {
			t.Fatalf("command line = %q, want %q", got, validCommandLine)
		}
	}
	for _, test := range []struct {
		name     string
		contents []byte
		want     string
	}{
		{"empty", nil, "between 1 and 2047"},
		{"only newline", []byte("\n"), "between 1 and 2047"},
		{"two lines", []byte("first\nsecond\n"), "line breaks"},
		{"CRLF", []byte("line\r\n"), "line breaks"},
		{"NUL", []byte("line\x00value\n"), "NUL"},
		{"quoted", []byte(`root="fstab value"`), "double quotes"},
		{"non-ASCII", []byte("root=fstab\u00a0quiet"), "printable ASCII"},
		{"tab", []byte("root=fstab\tquiet"), "printable ASCII"},
		{"backslash escape", []byte(`root=fstab\ quiet`), "backslash escapes"},
		{"repeated spaces", []byte("root=fstab  quiet"), "exactly one ASCII space"},
		{"kernel argument terminator", []byte("root=fstab -- quiet"), "argument terminator"},
		{"oversized", bytes.Repeat([]byte{'x'}, MaxCommandLineBytes+2), "exceeds 2047"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCommandLineFile(test.contents)
			assertErrorContains(t, err, test.want)
		})
	}
}

func TestParseCommandLineFileAcceptsExactArm64PayloadAndTrailingLF(t *testing.T) {
	commandLine := commandLineWithRequiredUARTSuffix(t, MaxCommandLineBytes)
	got, err := ParseCommandLineFile(append([]byte(commandLine), '\n'))
	if err != nil {
		t.Fatalf("ParseCommandLineFile at arm64 limit: %v", err)
	}
	if got != commandLine {
		t.Fatalf("parsed command-line length = %d, want %d", len(got), len(commandLine))
	}
}

func TestParseDeviceTreeRejectsStructureAmbiguity(t *testing.T) {
	valid := buildTestDeviceTree(defaultTreeOptions())
	structureOffset := int(binary.BigEndian.Uint32(valid[8:12]))
	for _, test := range []struct {
		name  string
		token uint32
		want  string
	}{
		{"unknown token", 0xfeedface, "unknown structure token"},
		{"premature end node", fdtEndNode, "unmatched end-node"},
		{"premature end", fdtEnd, "before closing the root"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := append([]byte(nil), valid...)
			binary.BigEndian.PutUint32(candidate[structureOffset:structureOffset+4], test.token)
			_, err := parseDeviceTree(candidate)
			assertErrorContains(t, err, test.want)
		})
	}
}

func replaceConsole(replacement string) string {
	return strings.Replace(validCommandLine, "console=ttyAMA10,115200n8", replacement, 1)
}

func commandLineWithRequiredUARTSuffix(t *testing.T, length int) string {
	t.Helper()
	suffix := " " + validCommandLine
	prefixBytes := length - len(suffix)
	if prefixBytes < len("padding=") {
		t.Fatalf("requested command-line length %d is too short for fixture", length)
	}
	commandLine := "padding=" + strings.Repeat("x", prefixBytes-len("padding=")) + suffix
	if len(commandLine) != length {
		t.Fatalf("fixture command-line length = %d, want %d", len(commandLine), length)
	}
	return commandLine
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}

const testDebugUARTPath = "/soc@107c000000/serial@7d001000"

type testMemoryRegion struct {
	address uint64
	size    uint64
}

type testTreeOptions struct {
	rootCompatible  []string
	memoryRegions   []testMemoryRegion
	omitMemory      bool
	debugAlias      string
	omitDebugAlias  bool
	extraAliases    []testProperty
	debugStatus     string
	omitDebugStatus bool
	debugCompatible []string
	debugRegister   uint32
	socParentBase   uint64
	stdoutPath      string
	omitStdout      bool
}

func defaultTreeOptions() testTreeOptions {
	return testTreeOptions{
		rootCompatible:  []string{"raspberrypi,5-model-b", "brcm,bcm2712"},
		memoryRegions:   []testMemoryRegion{{address: 0, size: 1024 * 1024 * 1024}},
		debugAlias:      testDebugUARTPath,
		debugStatus:     "okay",
		debugCompatible: []string{"arm,pl011-axi", "arm,pl011", "arm,primecell"},
		debugRegister:   0x7d001000,
		socParentBase:   0x10_00000000,
		stdoutPath:      "serial10:115200n8",
	}
}

type testProperty struct {
	name  string
	value []byte
}

type testNode struct {
	name       string
	properties []testProperty
	children   []testNode
}

func buildTestDeviceTree(options testTreeOptions) []byte {
	rootProperties := []testProperty{
		{"#address-cells", cells(2)},
		{"#size-cells", cells(2)},
		{"compatible", stringListProperty(options.rootCompatible...)},
		{"model", stringProperty("Raspberry Pi 5 Model B Rev 1.1")},
	}
	children := make([]testNode, 0, 5)
	if !options.omitMemory {
		reg := make([]uint32, 0, len(options.memoryRegions)*4)
		for _, region := range options.memoryRegions {
			reg = append(reg, uint32(region.address>>32), uint32(region.address), uint32(region.size>>32), uint32(region.size))
		}
		children = append(children, testNode{
			name: "memory@0",
			properties: []testProperty{
				{"device_type", stringProperty("memory")},
				{"reg", cells(reg...)},
			},
		})
	}
	debugProperties := []testProperty{
		{"compatible", stringListProperty(options.debugCompatible...)},
		{"reg", cells(options.debugRegister, 0x200)},
	}
	if !options.omitDebugStatus {
		debugProperties = append(debugProperties, testProperty{"status", stringProperty(options.debugStatus)})
	}
	children = append(children, testNode{
		name: "soc@107c000000",
		properties: []testProperty{
			{"#address-cells", cells(1)},
			{"#size-cells", cells(1)},
			{"ranges", cells(0, uint32(options.socParentBase>>32), uint32(options.socParentBase), 0x80000000)},
		},
		children: []testNode{{name: "serial@7d001000", properties: debugProperties}},
	})
	children = append(children, testNode{
		name: "axi",
		properties: []testProperty{
			{"#address-cells", cells(2)},
			{"#size-cells", cells(2)},
			{"ranges", []byte{}},
		},
		children: []testNode{{
			name: "serial@30000",
			properties: []testProperty{
				{"compatible", stringListProperty("arm,pl011-axi")},
				{"status", stringProperty("disabled")},
			},
		}},
	})
	aliases := []testProperty{{"serial0", stringProperty("/axi/serial@30000")}}
	if !options.omitDebugAlias {
		aliases = append(aliases, testProperty{debugUARTAlias, stringProperty(options.debugAlias)})
	}
	aliases = append(aliases, options.extraAliases...)
	children = append(children, testNode{name: "aliases", properties: aliases})
	chosenProperties := []testProperty{}
	if !options.omitStdout {
		chosenProperties = append(chosenProperties, testProperty{"stdout-path", stringProperty(options.stdoutPath)})
	}
	children = append(children, testNode{name: "chosen", properties: chosenProperties})
	return encodeTestFDT(testNode{name: "", properties: rootProperties, children: children})
}

func encodeTestFDT(root testNode) []byte {
	propertyOffsets := make(map[string]uint32)
	var stringTable bytes.Buffer
	var structure bytes.Buffer
	var emitNode func(testNode)
	emitNode = func(node testNode) {
		writeCell(&structure, fdtBeginNode)
		structure.WriteString(node.name)
		structure.WriteByte(0)
		pad4(&structure)
		for _, property := range node.properties {
			offset, exists := propertyOffsets[property.name]
			if !exists {
				offset = uint32(stringTable.Len())
				propertyOffsets[property.name] = offset
				stringTable.WriteString(property.name)
				stringTable.WriteByte(0)
			}
			writeCell(&structure, fdtProperty)
			writeCell(&structure, uint32(len(property.value)))
			writeCell(&structure, offset)
			structure.Write(property.value)
			pad4(&structure)
		}
		for _, child := range node.children {
			emitNode(child)
		}
		writeCell(&structure, fdtEndNode)
	}
	emitNode(root)
	writeCell(&structure, fdtEnd)

	const reservationOffset = fdtHeaderLen
	const reservationSize = 16
	structureOffset := reservationOffset + reservationSize
	stringsOffset := structureOffset + structure.Len()
	totalSize := stringsOffset + stringTable.Len()
	result := make([]byte, totalSize)
	for index, value := range []uint32{
		fdtMagic,
		uint32(totalSize),
		uint32(structureOffset),
		uint32(stringsOffset),
		reservationOffset,
		fdtVersion,
		16,
		0,
		uint32(stringTable.Len()),
		uint32(structure.Len()),
	} {
		binary.BigEndian.PutUint32(result[index*4:index*4+4], value)
	}
	copy(result[structureOffset:stringsOffset], structure.Bytes())
	copy(result[stringsOffset:], stringTable.Bytes())
	return result
}

func cells(values ...uint32) []byte {
	result := make([]byte, len(values)*4)
	for index, value := range values {
		binary.BigEndian.PutUint32(result[index*4:index*4+4], value)
	}
	return result
}

func stringProperty(value string) []byte {
	return append([]byte(value), 0)
}

func stringListProperty(values ...string) []byte {
	return append([]byte(strings.Join(values, "\x00")), 0)
}

func writeCell(output *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	output.Write(encoded[:])
}

func pad4(output *bytes.Buffer) {
	for output.Len()%4 != 0 {
		output.WriteByte(0)
	}
}
