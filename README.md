# dump-tls-cert

- Dumps TLS certificate chain presented by remote `host:port` in PEM format
- Uses TLS over TCP to connect to the remote `host:port`
- The certificate is dumped to STDOUT and written to a file `server-cert.pem`
- Does not verify the remote SSL/TLS certificate presented by the remote `host:port`

### Usage

```bash
go build -o dump-tls-cert .

❯ ./dump-tls-cert -help               
Usage of ./dump-tls-cert:
  -file string
        output file where the certificate will be written (default "server-cert.pem")
  -host string
        host name to connect to example www.google.com
  -port string
        port to connect to (default "443")

❯ ./dump-tls-cert -host www.google.com

-----BEGIN CERTIFICATE-----
MIIEhjCCA26gAwIBAgIQCXgy3jpYKBwKAAAAATeKJTANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMjAyMTcxMTMyNDJaFw0yMjA1MTIx
MTMyNDFaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEohOrV3nlStzyCwZKtbN+5JynBRLY8krpctM9DjBFMjMDtXjE
Ryd0/mW/H+iDJAO2QIsDvjgGqIjOn56V2Ma3YaOCAmYwggJiMA4GA1UdDwEB/wQE
AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBSeludtV1wHPLrcw016NhyHp/HWGTAfBgNVHSMEGDAWgBSKdH+vhc3ulc09nNDi
RhTzcTUdJzBqBggrBgEFBQcBAQReMFwwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3Nw
LnBraS5nb29nL2d0czFjMzAxBggrBgEFBQcwAoYlaHR0cDovL3BraS5nb29nL3J
...
...
...
...

❯ cat server-cert.pem

````