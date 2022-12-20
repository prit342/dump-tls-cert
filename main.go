package main

import (
	"dump-tls-cert/internal/certs"
	"flag"
	"io"
	"log"
	"os"
)

func main() {
	
	var host string
	var port string
	var file string
	
	flag.StringVar(&host, "host", "www.example.com", "host name to connect to example www.google.com")
	flag.StringVar(&port, "port", "443", "port to connect to")
	flag.StringVar(&file, "file", "server-cert.pem", "output file where the certificate will be written")
	
	flag.Parse()
	
	client := certs.TLSClient{
		Protocol: "tcp",
		Host:     host,
		Port:     port,
	}
	
	f, err := os.OpenFile(file, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	
	defer func() {
		if err := f.Close(); err != nil {
			log.Fatalln(err)
		}
	}()
	
	if err != nil {
		log.Fatalln(err)
	}
	
	mw := io.MultiWriter(os.Stdout, f)
	
	if err := certs.GetCertFromHostPortInPEM(&client, mw); err != nil {
		log.Fatalln(err)
	}
	
}
