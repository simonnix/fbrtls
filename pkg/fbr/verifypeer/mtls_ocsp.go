package verifypeer

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/client"
	"github.com/simonnix/fbrtls/pkg/fbr"
	"golang.org/x/crypto/ocsp"
)

type MTLSWithOSCPServerCertificateCustomizer struct {
	// ClientCertificate is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CA certificate.
	//
	// Default: ""
	ClientCertificate string

	OSCPServer string

	// TLSProvider add an external interface to configure a ClientTLSConfigProvider with the Fetch HTTP client
	//
	// Default: nil
	TLSProvider fbr.ClientTLSConfigProvider

	// Default: 1 * time.Seconds
	FetchClientTimeout time.Duration

	Storage fiber.Storage
}

var _ fbr.ServerCertificateCustomizer = &MTLSWithOSCPServerCertificateCustomizer{}

// CustomizeServerCertificate implements [fbr.ServerCertificateCustomizer].
func (m *MTLSWithOSCPServerCertificateCustomizer) CustomizeServerCertificate(config *tls.Config) error {
	var clientCACert *x509.Certificate

	mtls := &fbr.MTLSServerCertificateCustomizer{
		ClientCertificate: m.ClientCertificate,
	}

	if m.FetchClientTimeout == 0 {
		m.FetchClientTimeout = 10 * time.Second
	}

	if err := mtls.CustomizeServerCertificate(config); err != nil {
		return err
	} else if clientCACert = mtls.GetCACertificate(); clientCACert == nil {
		return nil
	}

	var ocspServer string

	validateOSCPServer := func(ocspServer string) error {
		if distUrl, err := url.Parse(ocspServer); err != nil {
			return err
		} else if !slices.Contains([]string{"http", "https"}, distUrl.Scheme) {
			return fmt.Errorf("tls: OCSP Stapling: wrong scheme=%q, only 'http' or 'https' is supported", distUrl.Scheme)
		}
		return nil
	}

	if m.OSCPServer != "" {
		if err := validateOSCPServer(m.OSCPServer); err == nil {
			ocspServer = m.OSCPServer
		}
	} else {
		for _, ocsp := range clientCACert.OCSPServer {
			if err := validateOSCPServer(ocsp); err == nil {
				ocspServer = ocsp
				break
			}
		}
	}

	if ocspServer != "" {
		cc := fbr.NewClient()
		cc.SetTimeout(m.FetchClientTimeout)

		ocspUrl, _ := url.Parse(ocspServer)
		if ocspUrl.Scheme == "https" {
			cc.SetTLSProvider(m.TLSProvider)
		}

		config.VerifyPeerCertificate = func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
			cert := verifiedChains[0][0]
			opts := &ocsp.RequestOptions{Hash: crypto.SHA256}
			buffer, err := ocsp.CreateRequest(cert, clientCACert, opts)
			if err != nil {
				return err
			}
			req := client.AcquireRequest()
			defer client.ReleaseRequest(req)

			req.SetClient(cc.GetClient())
			req.AddHeader("Content-Type", "application/ocsp-request")
			req.AddHeader("Accept", "application/ocsp-response")
			req.SetRawBody(buffer)

			resp, err := req.Post(ocspServer)
			if err != nil {
				return err
			}
			defer resp.Close()
			ocspResponse, err := ocsp.ParseResponseForCert(resp.Body(), cert, clientCACert)
			if err != nil {
				return err
			}

			switch ocspResponse.Status {
			case ocsp.Good:
				fmt.Printf("Certificate status is Good\n")
			case ocsp.Revoked:
				fmt.Printf("Certificate status is Revoked\n")
				return fmt.Errorf("tls: the certificate was revoked")
			case ocsp.Unknown:
				fmt.Printf("Certificate status is Unknown\n")
				return fmt.Errorf("tls: the certificate is unknown to OCSP server")
			}

			return nil
		}
	}

	return nil
}
