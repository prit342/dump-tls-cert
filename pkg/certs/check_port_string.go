// Package certs provides functionality to retrieve and handle TLS certificates from remote hosts.
package certs

import (
	"fmt"
	"strconv"
	"strings"
)

// CheckPort - validates if a string is a valid TCP/UDP port
func checkPort(port string) error {
	portN, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("unable to convert PORT number %s to integer - %w", port, err)
	}

	if portN > 65535 || portN < 1 {
		return fmt.Errorf("invalid port %q: %w", port, ErrInvalidPortRange)
	}

	return nil
}

// isEmptyString - validates in a string is empty
func isEmptyString(s string) bool {
	if s := strings.TrimSpace(s); s == "" {
		return true
	}
	return false
}
