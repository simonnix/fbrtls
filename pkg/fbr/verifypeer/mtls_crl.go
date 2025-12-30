package verifypeer

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/simonnix/fbrtls/pkg/fbr"
)

// MTLSWithCRLServerCertificateCustomizer is a struct implementing ServerCertificateCustomizer.
//
// NOTE: Only CRL version 2 in PEM format is supported.
// See: https://docs.openssl.org/3.5/man1/openssl-ca/#crl-options
type MTLSWithCRLServerCertificateCustomizer struct {
	// ClientCertificate is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CA certificate.
	//
	// Default: ""
	ClientCertificate string

	// RevocationList is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CRL in version 2.
	//
	// Default: ""
	RevocationList string

	// FetchRevocationList when true will try to fetch the CRL from either the RevocationListURL or from
	// the CA certificate "CRL distribution point".
	// See: https://docs.openssl.org/3.5/man5/x509v3_config/#crl-distribution-points
	//
	// Default: false
	FetchRevocationList bool

	// RevocationListURL represent an URL to fetch the CRL from instead of a configured "CRL distribution point".
	//
	// Default: ""
	RevocationListURL string

	// TLSProvider add an external interface to configure a ClientTLSConfigProvider with the Fetch HTTP client
	//
	// Default: nil
	TLSProvider fbr.ClientTLSConfigProvider

	// Default: 10 * time.Seconds
	FetchClientTimeout time.Duration
}

var _ fbr.ServerCertificateCustomizer = &MTLSWithCRLServerCertificateCustomizer{}

// CustomizeServerCertificate implements ServerCertificateCustomizer
// It uses MTLSServerCertificateCustomizer to first set up mTLS, but adds Certificate Revocation List support.
// The CRL can be provided, using a file path or its content). It can also be fetching from a provider URL
// or using the URL in the CA certificate.
func (m *MTLSWithCRLServerCertificateCustomizer) CustomizeServerCertificate(config *tls.Config) error {
	var clientCACert *x509.Certificate

	mtls := &fbr.MTLSServerCertificateCustomizer{
		ClientCertificate: m.ClientCertificate,
	}

	if err := mtls.CustomizeServerCertificate(config); err != nil {
		return err
	} else if clientCACert = mtls.GetCACertificate(); clientCACert == nil {
		return nil // NOTE Should it return an error
	}

	fetch_crl := func(dist string) ([]byte, error) {
		cc := fbr.NewClient()
		cc.SetTimeout(m.FetchClientTimeout)

		if distUrl, err := url.Parse(dist); err != nil {
			return []byte{}, err
		} else if !slices.Contains([]string{"http", "https"}, distUrl.Scheme) {
			return []byte{}, fmt.Errorf("tls: CRL fetching client: wrong scheme=%q, only 'http' or 'https' is supported", distUrl.Scheme)
		} else if distUrl.Scheme == "https" {
			cc.SetTLSProvider(m.TLSProvider)
		}
		if resp, err := cc.Get(dist); err != nil {
			return []byte{}, fmt.Errorf("tls: unable to fetch certificate revocation list from url=%q: %w", dist, err)
		} else if block, _ := pem.Decode([]byte(resp.Body())); block != nil && block.Type == "X509 CRL" {
			return block.Bytes, nil
		} else {
			return []byte{}, fmt.Errorf("tls: unable to parse PEM CRL from url=%q", dist)
		}
	}

	if m.FetchClientTimeout == 0 {
		m.FetchClientTimeout = 10 * time.Second
	}

	var clientCRL *x509.RevocationList
	var crlBytes []byte

	if m.RevocationList != "" {
		if block, _ := pem.Decode([]byte(m.RevocationList)); block != nil && block.Type == "X509 CRL" {
			crlBytes = block.Bytes
		} else if file, err := os.ReadFile(filepath.Clean(m.RevocationList)); err != nil {
			return fmt.Errorf("tls: failed to read CRL file from path=%q: %w", m.RevocationList, err)
		} else {
			crlBytes = file
		}
	}

	if m.FetchRevocationList {
		if m.RevocationListURL != "" {
			if file, err := fetch_crl(m.RevocationListURL); err != nil {
				return err
			} else {
				crlBytes = file
			}
		} else {
			for _, dist := range clientCACert.CRLDistributionPoints {
				if file, err := fetch_crl(dist); err == nil {
					crlBytes = file
					break
				}
			}
		}
	}

	if len(crlBytes) > 0 {
		if crl, err := x509.ParseRevocationList(crlBytes); err != nil {
			return fmt.Errorf("tls: unable to load CRL: %w", err)
		} else {
			clientCRL = crl
		}
	}

	if clientCRL != nil {
		config.VerifyPeerCertificate = func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
			cert := verifiedChains[0][0]
			for _, revokedCertificate := range clientCRL.RevokedCertificateEntries {
				if revokedCertificate.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					fmt.Println("tls: The certificate was revoked")
					return fmt.Errorf("tls: The certificate was revoked!")
				}
			}
			fmt.Println("tls: The certificate is not revoked.")
			return nil
		}
	}

	return nil
}
