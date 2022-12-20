package certs

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	url2 "net/url"
	"testing"
)

// State or Province Name (full name) [Some-State]:ENGLAND
// Country Name (2 letter code) [AU]:GB
// Locality Name (eg, city) []:LONDON
// Organization Name (eg, company) [Internet Widgits Pty Ltd]:example-org
// Organizational Unit Name (eg, section) []:IT
// Common Name (e.g. server FQDN or YOUR name) []:testserver.local
// Email Address []:hostmaster@testserver.local
const (
	serverCert = `-----BEGIN CERTIFICATE-----
MIIEFzCCAv+gAwIBAgIUcFHI/rDAqMY96GzvZSvHHsskMD0wDQYJKoZIhvcNAQEL
BQAwgZoxCzAJBgNVBAYTAkdCMRAwDgYDVQQIDAdFTkdMQU5EMQ8wDQYDVQQHDAZM
T05ET04xFDASBgNVBAoMC2V4YW1wbGUtb3JnMQswCQYDVQQLDAJJVDEZMBcGA1UE
AwwQdGVzdHNlcnZlci5sb2NhbDEqMCgGCSqGSIb3DQEJARYbaG9zdG1hc3RlckB0
ZXN0c2VydmVyLmxvY2FsMB4XDTIyMDMwOTEyMzQyNVoXDTMyMDMwNjEyMzQyNVow
gZoxCzAJBgNVBAYTAkdCMRAwDgYDVQQIDAdFTkdMQU5EMQ8wDQYDVQQHDAZMT05E
T04xFDASBgNVBAoMC2V4YW1wbGUtb3JnMQswCQYDVQQLDAJJVDEZMBcGA1UEAwwQ
dGVzdHNlcnZlci5sb2NhbDEqMCgGCSqGSIb3DQEJARYbaG9zdG1hc3RlckB0ZXN0
c2VydmVyLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn+kN
NbaZ+7vXzLAKfCCIlVDFivgqRJzzNUB4fv4ALtFUCOUhGqkovNbeXN+sOAh4L6vt
YbThTNXwF86q96Ngaxpg5+K3m7hx0F2U7FP00UtWLy7F/PBT2/f9arkQyB6nJD0D
UO3gX8mZVN/ZQg4scYmxN30cnYa5xhQ6w53CR/4U7T9Z4Xojf4jM3gRpOH3/woF2
XoCzOXRKQJriGjOd6DKyQtdRiYkhAYbCPkb4rPAkmTtRglS6S2QzOnSOACRQz9JV
AWrvleF4iIWNo/gKml/QaeTaFcwEPZCG5o0M1wScnfk/qPaNcgv+owzdCr0Cjnkj
iruKgdxmWpXFaHGeaQIDAQABo1MwUTAdBgNVHQ4EFgQUchA+CNnkUi2eu47oSXzx
6il/frEwHwYDVR0jBBgwFoAUchA+CNnkUi2eu47oSXzx6il/frEwDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAcaVDhjaYn34l7mag5I9vR4zFEoY9
J9O+W77tATrbSz9u+/3tpVGrMjQWMapwunlWi74aI1EhDsN47q8KtZaw68fTfOW2
3+e9GZ1mBkz90itQGs5TwUqoWpo61N3qjcUof96lb064AQ2pmNNBm+Go5VwiyqXx
tMvy6Nx/gduK+cvyx5qZRyTEzYJHkVBDRvQCDbtsA4wwtpdSpTqAYhHgQqq140Ze
j2MG8Z5/KiGx9LVYHBfC4HwwGNFtOoxADsNeD0RBSjjunfPNZzTLACkw++PORtcq
6q0VoM3Wf3WjX2pCCGJ3QDqJvzyk2QYeL7+JnFDKOloZQczkN2vuVx/l0w==
-----END CERTIFICATE-----
`
	serverKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCf6Q01tpn7u9fM
sAp8IIiVUMWK+CpEnPM1QHh+/gAu0VQI5SEaqSi81t5c36w4CHgvq+1htOFM1fAX
zqr3o2BrGmDn4rebuHHQXZTsU/TRS1YvLsX88FPb9/1quRDIHqckPQNQ7eBfyZlU
39lCDixxibE3fRydhrnGFDrDncJH/hTtP1nheiN/iMzeBGk4ff/CgXZegLM5dEpA
muIaM53oMrJC11GJiSEBhsI+Rvis8CSZO1GCVLpLZDM6dI4AJFDP0lUBau+V4XiI
hY2j+AqaX9Bp5NoVzAQ9kIbmjQzXBJyd+T+o9o1yC/6jDN0KvQKOeSOKu4qB3GZa
lcVocZ5pAgMBAAECggEAfJMCvnh9ZvXEPOpbkK2Lmb7t1cBUtVULxs1t0YiwvchH
ThKqAmoLmWlOm02IjbJTZtfqOva9ma0EuJdA62B0aZuIKL2fSgmbaLauoJkbHL0y
69jlVpIm0jNUUYLQxwXSMdHyNmbKJ/UWpV8pkmMWTnD1BQRLeZCOQvhZezD4PDpB
9ejO81Mu/30l1VOVz3KGxBaVgHr/6f5DLFRl4LVoYf4ATvCHg31pkXMomYbVqsrU
QSeM1nyPSyD3p7iysCA1wvNzDsYBMxaqC1stKvitJXVyJ6eFwOZL1OLGNNkazDK/
VnzXYv2ld3ZrIn0V6YvO3s5HUBAq1YAJOasJkEPdfQKBgQDLSeSf/CldR1ewFoDR
nCWWYwxYO8cBP7vDwUShTq4IfTilnN35VP9wthZtNmUk8sxRVmTvB2fv+rD9a6pe
zCa9g4/sSYPXbALfWAPAFGgoSPhOmx2ar/Bln1nNgKeSNH6jY+XuFpj+sw8SZQCi
oAIhkueDPQJv4aiv5POIQPfC4wKBgQDJX7/EnEXjCGF2dgGQNF/NLW3W0sgNzPFv
i2DP3VnTA+xIrwPygxsQqITODNLvFNlvMBC0c79l2OZCxquGiAJMoH82EZ3RJugl
D3zH+B5yfFAZAqwA4jwhF3Q/fBKZPXHA69U+U/0XlUFfqir5J2fd3aSzGaIVlpNM
wGoJ31l/QwKBgQC1FEAjRhFudmMkhhb/H3DX0aioW677bNMLHvfMG/KnuysfUmjj
dJQIyRmW9LIJxIC9HxDPXjB2Mj8/rYzX3k/P1gX4es+Grz6rxZGpokPZRo5wLnmj
VX70dooepLAfasU3M4AXoWds0QDm6LM1KQRc9adlXo3yLPb+nxlS0FQh8wKBgDWZ
is2mWuPHQ0notxnPFwDh6q6XhDBIMKtkCezKGjKUhLwD+aT/SKDyegbuWubQQd/a
h1fAx10wknmLr/QrF5GV1sZpgfw9wuS6bpg7br9CX3+IuoexsBeOyp5rQ/gN5s1W
+HeSm3c/fxsbjDytRHRFnqUdWYstfR+cx5zBGm1JAoGBAMgczBgkOrW+yq+umMlT
N1W08chATm/8qy8sWTmA+dHSCwsC6rceWAmfeJjW7ZOgrMdbWo7DpWhweSr9ZxnW
G1tOrmzJXM4/wXLDHUpnOW/1J7Vdrd8uxcWXHxBTBvuz5AccCua1hndtiDd6uPRY
Ckx9bdd0OfQ+wX1H1eYPVEa8
-----END PRIVATE KEY-----
`
)

func TestGetCertFromHostPortInPEM(t *testing.T) {
	
	t.Run("test with valid certificates", func(t *testing.T) {
		certChain, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
		
		require.NoError(t, err)
		
		testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK"))
		}))
		
		testServer.TLS = &tls.Config{
			Certificates: []tls.Certificate{certChain},
		}
		testServer.StartTLS()
		defer testServer.Close()
		
		//fmt.Println(testServer.URL)
		
		url, err := url2.Parse(testServer.URL)
		
		require.NoError(t, err)
		
		host, port, err := net.SplitHostPort(url.Host)
		
		require.NoError(t, err)
		
		client := TLSClient{
			Protocol: "tcp",
			Host:     host,
			Port:     port,
		}
		
		var b bytes.Buffer
		err = GetCertFromHostPortInPEM(&client, &b)
		require.NoError(t, err)
		
		require.Equal(t, b.String(), serverCert)
	})
	
	t.Run("test with invalid protocol", func(t *testing.T) {
		client := TLSClient{
			Protocol: "foobar",
			Host:     "localhost",
			Port:     "2222222",
		}
		
		err := GetCertFromHostPortInPEM(&client, io.Discard)
		fmt.Println(err)
		require.Error(t, err)
		
	})
	
	t.Run("test with invalid port", func(t *testing.T) {
		client := TLSClient{
			Protocol: "tcp",
			Host:     "localhost",
			Port:     "-1",
		}
		
		err := GetCertFromHostPortInPEM(&client, io.Discard)
		
		require.Error(t, err)
		
	})
	
}

func TestCheckPort(t *testing.T) {
	type args struct {
		port string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid port", args{"5000"}, false},
		{"invalid port >65535", args{"99999"}, true},
		{"invalid port -1", args{"-1"}, true},
		{"invalid port 0", args{"0"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			
			if err := CheckPort(tt.args.port); (err != nil) != tt.wantErr {
				t.Errorf("CheckPort() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsEmptyString(t *testing.T) {
	tests := []struct {
		s    string
		name string
		want bool
	}{
		{"    ", "test with empty string \"    \"", true},
		{"       ", "test with empty string \"       \"", true},
		{"", "test with empty string \"\"", true},
		{"\"\"", "test with non-emtpy string \"\\\"\\\"\"", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEmptyString(tt.s); got != tt.want {
				t.Errorf("IsEmptyString() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockClient struct{}

func (m *mockClient) TLSDial() ([]*x509.Certificate, error) {
	emptyReply := make([]*x509.Certificate, 1)
	return emptyReply, nil
}

func TestEmptyCertificateReply(t *testing.T) {
	m := &mockClient{}
	_, err := m.TLSDial()
	
	require.Nil(t, err)
	
	var b bytes.Buffer
	
	err = GetCertFromHostPortInPEM(m, &b)
	require.Error(t, err)
	
	require.Equal(t, "", b.String())
	
}
