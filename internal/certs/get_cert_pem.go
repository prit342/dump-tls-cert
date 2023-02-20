package certs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	protocol = "tcp" // The default Protocol that we use
)

var (
	// ErrNoCertsReturned - no TLS certs were returned by the remote Peer
	ErrNoCertsReturned = errors.New("no TLS certificates were found")
	// ErrInvalidPortRange - Invalid port range
	ErrInvalidPortRange = errors.New("invalid port range, port number should be <= 65535 and >= 1")
	// ErrEmptyHost - empty host string was encountered
	ErrEmptyHost = errors.New("host cannot be empty string")
)

// TLSDialer - dials a remote host over TCP to grab x509 certs
type TLSDialer interface {
	TLSDial() ([]*x509.Certificate, error)
}

type TLSClient struct {
	Host       string // Host to connect to
	Port       string // Port to connect to
	SkipVerify bool   // skip verification of the TLS cert presetned by Host:Port
}

// NewTLSClient returns a new instance of a TLSClient
func NewTLSClient(host, port string, skipverify bool) *TLSClient {
	return &TLSClient{
		Host:       host,
		Port:       port,
		SkipVerify: skipverify,
	}
}

// Check if TLSClient implements the TLSDialer interface
var _ TLSDialer = (*TLSClient)(nil)

// TLSDial - Dial a Host and Port over TLS and retrieves the certificate chain
func (tc *TLSClient) TLSDial() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	config := &tls.Config{
		InsecureSkipVerify: tc.SkipVerify,
		ServerName:         tc.Host,
	}

	if err := CheckPort(tc.Port); err != nil {
		return certs, fmt.Errorf("invalid port: %w", err)
	}

	if ok := IsEmptyString(tc.Host); ok {
		return certs, ErrEmptyHost
	}

	target := net.JoinHostPort(tc.Host, tc.Port)

	conn, err := tls.Dial(protocol, target, config)

	defer func(conn *tls.Conn) {
		if conn == nil {
			return
		}
		if err := conn.Close(); err != nil {
			fmt.Println(err)
		}
	}(conn)

	if err != nil {
		return certs, fmt.Errorf("unable to dial %s://%s - %w", protocol, target, err)
	}

	state := conn.ConnectionState()

	if len(state.PeerCertificates) < 1 {
		return nil, fmt.Errorf("no certificates found for %s: %w", target, ErrNoCertsReturned)
	}

	return state.PeerCertificates, nil
}

// GetCert - uses TLSDialer to dial remote host and grab the TLS certificate in PEM format
func GetCert(td TLSDialer, w io.Writer) error {
	// get the certs
	certs, err := td.TLSDial()
	if err != nil {
		return err
	}

	var b bytes.Buffer

	for _, cert := range certs {
		if cert == nil {
			continue
		}

		err := pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return err
		}
	}

	pemCert := b.String()

	if pemCert == "" {
		return fmt.Errorf("no certs were returned by the remote peer: %w", ErrNoCertsReturned)
	}

	_, err = io.Copy(w, &b)

	if err != nil {
		return err
	}

	return nil
}

// CheckPort - validates if a string is a valid TCP/UDP port
func CheckPort(port string) error {
	portN, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("unable to convert PORT number %s to integer - %w", port, err)
	}

	if portN > 65535 || portN < 1 {
		return fmt.Errorf("invalid port %q: %w", port, ErrInvalidPortRange)
	}

	return nil
}

// IsEmptyString - validates in a string is empty
func IsEmptyString(s string) bool {
	if s := strings.TrimSpace(s); s == "" {
		return true
	}
	return false
}
