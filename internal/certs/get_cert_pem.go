package certs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const (
	LayerFourProtocol = "tcp"
)

// TLSClient  holds a new TLS Client
type TLSClient struct {
	Protocol string
	Host     string
	Port     string
}

// NewTLSClient returns a new instance of a TLSClient
func NewTLSClient(protocol, host, port string) *TLSClient {
	
	return &TLSClient{
		Host:     host,
		Port:     port,
		Protocol: protocol,
	}
}

type TLSDialer interface {
	TLSDial() ([]*x509.Certificate, error)
}

//// TLSDialOverHTTPSProxy - dials over an HTTPS proxy server
//func TLSDialOverHTTPSProxy() error {
//
//	u, err := url.Parse("http://localhost:3128")
//	//
//	if err != nil {
//		log.Fatalln(err)
//	}
//	tlsConfig := &tls.Config{
//		InsecureSkipVerify: true,
//	}
//
//	tunnelDialer := gdialer.New(u, gdialer.WithConnectionTimeout(7*time.Second))
//	conn, err := tunnelDialer.Dial("tcp", "www.google.com:443")
//
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	var b []byte
//	_, err = conn.Read(b)
//
//	if err != nil {
//		log.Fatalln(err)
//	}
//
//	fmt.Println(string(b))
//
//	tls.Client(conn, tlsConfig)
//
//	return nil
//}

// TLSDial - Dial a Host and Port over TLS and get the certificate chain
func (tc *TLSClient) TLSDial() ([]*x509.Certificate, error) {
	
	var certs []*x509.Certificate
	
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         tc.Host,
	}
	
	if err := CheckPort(tc.Port); err != nil {
		return certs, err
	}
	
	tc.Protocol = strings.ToLower(tc.Protocol)
	
	if ok := IsEmptyString(tc.Protocol); ok {
		return certs, fmt.Errorf("protocol cannot be empty string")
	}
	
	if ok := IsEmptyString(tc.Host); ok {
		return certs, fmt.Errorf("host cannot be empty string")
	}
	
	if tc.Protocol != LayerFourProtocol {
		return certs, fmt.Errorf("only %s protocol is supported, not %s", LayerFourProtocol, tc.Protocol)
	}
	
	target := tc.Host + ":" + tc.Port
	
	conn, err := tls.Dial(tc.Protocol, target, config)
	
	defer func() {
		if conn == nil {
			return
		}
		if err := conn.Close(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}()
	
	if err != nil {
		return certs, fmt.Errorf("unable to dial %s://%s - %w", tc.Protocol, target, err)
	}
	
	certs = conn.ConnectionState().PeerCertificates
	
	if len(certs) < 1 {
		return nil, fmt.Errorf("no certs were returned by the server %s", target)
	}
	
	return certs, nil
	
}

// GetCertFromHostPortInPEM - Gets a certificate chain in PEM format from a host over TCP
func GetCertFromHostPortInPEM(d TLSDialer, out io.Writer) error {
	
	certs, err := d.TLSDial()
	
	if err != nil {
		return err
	}
	
	//fmt.Println(certs)
	
	if certs == nil || len(certs) < 1 {
		return fmt.Errorf("no certs were returned by the server")
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
		return fmt.Errorf("no certs were returned by the server")
	}
	
	_, err = io.Copy(out, &b)
	
	if err != nil {
		return err
	}
	
	return nil
}

// CheckPort - validates if a string is a valid TCP/UDP port
func CheckPort(port string) error {
	
	portN, err := strconv.Atoi(port)
	
	if err != nil {
		return fmt.Errorf("unable to convert PORT number %v to integer - %w", port, err)
	}
	
	if portN > 65535 || portN < 1 {
		return fmt.Errorf("invalid port %q, port number should be <= 65535 and >= 1", port)
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
