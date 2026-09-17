package yubikeysigner

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// These are the reason strings registered by the pinned pkcs11-provider 1.2.0
// in src/provider.c:p11prov_get_reason_strings. Only our constant CKR names
// leave this package. Provider text, paths, URIs and error.Error() never do.
// A reported code is diagnostic evidence, not proof of the physical cause or
// permission to retry an operation with ambiguous private-key use.
var knownPKCS11Reasons = []struct {
	code   uint64
	name   string
	reason string
}{
	{0x05, "CKR_GENERAL_ERROR", "General Error"},
	{0x06, "CKR_FUNCTION_FAILED", "The requested function could not be performed"},
	{0x30, "CKR_DEVICE_ERROR", "Some problem has occurred with the token and/or slot"},
	{0x32, "CKR_DEVICE_REMOVED", "The token was removed from its slot during the execution of the function"},
	{0x50, "CKR_FUNCTION_CANCELED", "The function was canceled in mid-execution"},
	{0x60, "CKR_KEY_HANDLE_INVALID", "The specified key handle is not valid"},
	{0x68, "CKR_KEY_FUNCTION_NOT_PERMITTED", "The key attributes do not allow this operation to be executed"},
	{0x70, "CKR_MECHANISM_INVALID", "An invalid mechanism was specified to the cryptographic operation"},
	{0x71, "CKR_MECHANISM_PARAM_INVALID", "Invalid mechanism parameters were supplied"},
	{0x90, "CKR_OPERATION_ACTIVE", "There is already an active operation that prevents executing the requested function"},
	{0x91, "CKR_OPERATION_NOT_INITIALIZED", "There is no active operation of appropriate type in the specified session"},
	{0xa0, "CKR_PIN_INCORRECT", "The specified PIN is incorrect"},
	{0xa1, "CKR_PIN_INVALID", "The specified PIN is invalid"},
	{0xa3, "CKR_PIN_EXPIRED", "The specified PIN has expired"},
	{0xa4, "CKR_PIN_LOCKED", "The specified PIN is locked, and cannot be used"},
	{0xb0, "CKR_SESSION_CLOSED", "Session is already closed"},
	{0xb1, "CKR_SESSION_COUNT", "Too many sessions open"},
	{0xb3, "CKR_SESSION_HANDLE_INVALID", "Invalid Session Handle"},
	{0xe0, "CKR_TOKEN_NOT_PRESENT", "The token was not present in its slot when the function was invoked"},
	{0xe1, "CKR_TOKEN_NOT_RECOGNIZED", "The token in the slot is not recognized"},
	{0x101, "CKR_USER_NOT_LOGGED_IN", "The desired action cannot be performed because an appropriate user is not logged in"},
	{0x190, "CKR_CRYPTOKI_NOT_INITIALIZED", "PKCS11 Module has not been initialized yet"},
}

func commandFailure(stage string, result Result, err error) error {
	process := "process_failure"
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if code := exit.ExitCode(); code >= 0 && code <= 255 {
			process = fmt.Sprintf("exit_status=%d", code)
		} else {
			process = "process_terminated"
		}
	}
	return fmt.Errorf("%s command failed (%s; pkcs11=%s; raw diagnostics withheld)",
		stage, process, pkcs11FailureCodes(result.Stderr))
}

func pkcs11FailureCodes(stderr []byte) string {
	// Refuse oversized diagnostics even for alternate Runner implementations.
	if len(stderr) > maxDiagnosticBytes {
		return "unclassified"
	}
	found := make(map[uint64]bool)
	for _, line := range strings.Split(string(stderr), "\n") {
		// OpenSSL ERR_print_errors format:
		// thread:error:packed-code:library:function:reason:file:line:data
		fields := strings.SplitN(line, ":", 8)
		if len(fields) != 8 || fields[1] != "error" || fields[3] != "pkcs11" ||
			!hexField(fields[0], 32) || len(fields[2]) != 8 || !hexField(fields[2], 8) {
			continue
		}
		packed, _ := strconv.ParseUint(fields[2], 16, 32)
		// OpenSSL 3 ERR_GET_REASON masks the lower 23 bits. The provider's
		// dynamically allocated library number is not a stable identifier.
		code := packed & 0x7fffff
		for _, known := range knownPKCS11Reasons {
			if code == known.code && fields[5] == known.reason {
				found[code] = true
				break
			}
		}
	}
	var names []string
	for _, known := range knownPKCS11Reasons {
		if found[known.code] {
			names = append(names, known.name)
		}
	}
	if len(names) == 0 {
		return "unclassified"
	}
	return strings.Join(names, ",")
}

func hexField(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
