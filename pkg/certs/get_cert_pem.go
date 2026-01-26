// Package certs provides functionality to retrieve and handle TLS certificates from remote hosts.
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

// TLSCertGetter - dials a remote host over TCP to grab x509 certs
type TLSCertGetter interface {
	GetCert(w io.Writer) error
}

// tlsClient - client that can perfrom TLS Dial over TCP
type tlsClient struct {
	Host       string // Host to connect to
	Port       string // Port to connect to
	SkipVerify bool   // skip verification of the TLS cert presetned by Host:Port
}

// NewTLSClient returns a new instance of a TLSClient
func NewTLSClient(host, port string, skipverify bool) TLSCertGetter {
	return &tlsClient{
		Host:       host,
		Port:       port,
		SkipVerify: skipverify,
	}
}

// Check if TLSClient implements the TLSDialer interface
var _ TLSCertGetter = (*tlsClient)(nil)

// GetCert - uses TLSDialer to dial remote host and grab the TLS certificate in PEM format
func (tc *tlsClient) GetCert(w io.Writer) error {

	if w == nil {
		return errors.New("invalid write sent")
	}

	if tc == nil {
		return errors.New("invalid TLS client")
	}

	// get the certs
	certs, err := tc.tlsDial()
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

// tlsDial - Dials a Host and Port over TLS and retrieves the certificate chain
func (tc *tlsClient) tlsDial() (certs []*x509.Certificate, err error) {

	config := &tls.Config{
		InsecureSkipVerify: tc.SkipVerify, // #nosec G402 -- intentionally configurable for testing
		ServerName:         tc.Host,
	}

	if errC := checkPort(tc.Port); errC != nil {
		err = fmt.Errorf("invalid port: %w", errC)
		return
	}

	if ok := isEmptyString(tc.Host); ok {
		err = ErrEmptyHost
		return
	}

	target := net.JoinHostPort(tc.Host, tc.Port)

	conn, err := tls.Dial(protocol, target, config)

	if err != nil {
		err = fmt.Errorf("unable to dial %s://%s - %w", protocol, target, err)
		return
	}

	defer func() {
		if conn == nil { // ensure we don't panic
			return
		}
		if closeErr := conn.Close(); closeErr != nil { // close the connection
			err = errors.Join(err, closeErr) // return both the errors
		}
	}()

	state := conn.ConnectionState()

	if len(state.PeerCertificates) < 1 {
		err = fmt.Errorf("no certificates found for %s: %w", target, ErrNoCertsReturned)
		return
	}

	certs = state.PeerCertificates
	return
}
