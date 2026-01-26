// Package main provides a command-line tool to dump TLS certificates from remote hosts.
package main

import (
	"flag"
	"io"
	"log"
	"os"

	"dump-tls-cert/pkg/certs"
)

func main() {
	var (
		host          string
		port          string
		file          string
		skipTLSVerify bool
	)

	flag.StringVar(&host, "host", "", "host name to connect to example www.google.com")
	flag.StringVar(&port, "port", "443", "port to connect to")
	flag.BoolVar(&skipTLSVerify, "skip", true, "skip verification of TLS certs")
	flag.StringVar(&file, "file", "server-cert.pem", "output file where the certificate will be written")

	flag.Parse()

	if host == "" {
		flag.Usage()
		log.Fatalln("host parameter is missing")
	}

	c := certs.NewTLSClient(host, port, skipTLSVerify)

	// open a file to write
	f, err := os.OpenFile(file, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- file path is user-provided via CLI flag

	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalln("unable to close file handle", err)
		}
	}()

	if err != nil {
		log.Fatalln(err)
	}

	// create a multi writer to write the data to STDOUT and file
	mw := io.MultiWriter(os.Stdout, f)

	if err := c.GetCert(mw); err != nil {
		log.Fatalln(err)
	}
}
