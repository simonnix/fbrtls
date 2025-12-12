/*
Copyright © 2025 Simon HUET

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package fbr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/gofiber/fiber/v3"
)

// ServerTLSConfigProvider is an interface used by ListenConfig to obtain a *tls.Config.
type ServerTLSConfigProvider interface {
	// ProvideServerTLSConfig provides possibly a *tls.Config object to be used by Listen or
	// an error if it failed to do so.
	//
	// NOTE: It may return nil, nil if no tls.Config can be provided and it not being an error.
	ProvideServerTLSConfig() (*tls.Config, error)
}

// ListenConfig is a local version of fiber.ListenConfig with an added field TLSProvider field.
type ListenConfig struct {
	// ListenConfig composite
	fiber.ListenConfig

	// TLSProvider add an external interface to provide a *tls.Config object for this ListenConfig
	//
	// Default: nil
	TLSProvider ServerTLSConfigProvider
}

func DefaultListenConfig() ListenConfig {
	return ListenConfig{
		ListenConfig: fiber.ListenConfig{
			TLSMinVersion:      tls.VersionTLS12,
			ListenerNetwork:    NetworkTCP4,
			UnixSocketFileMode: 0o770,
			ShutdownTimeout:    10 * time.Second,
		},
	}
}

// Listen is a local version of fiber.App.Listen().
// It implements TLS using ListenConfig.TLSProvider.
func (app *App) Listen(addr string, cfg ListenConfig) error {

	// Will use app.App.Listen is prefork
	if cfg.EnablePrefork {
		return app.App.Listen(addr, cfg.ListenConfig)
	}

	var tlsConfig *tls.Config

	// Get tls.Config if configured
	if cfg.TLSProvider != nil {
		if tc, err := cfg.TLSProvider.ProvideServerTLSConfig(); err != nil {
			return err
		} else {
			tlsConfig = tc
		}
	}

	// Will use app.App.Listen if no *tls.Config
	if tlsConfig == nil {
		return app.App.Listen(addr, cfg.ListenConfig)
	}

	// Calling app.Listener as it's not possible to use directly Listen for now.
	ln, _ := net.Listen("tcp", addr)
	ln = tls.NewListener(ln, tlsConfig)
	return app.Listener(ln)
}

// ServerCertificateCustomizer provides an interface for ServerCertificateProvider to use a named
// external extra customizer to its *tls.Config object.
type ServerCertificateCustomizer interface {
	CustomizeServerCertificate(config *tls.Config) error
}

// ServerCertificateProvider is a struct implementing ServerTLSConfigProvider, to be used with ListenConfig.
type ServerCertificateProvider struct {
	// CertificateChain is either a path to a file or the content of the file instead.
	//
	// It must contain, in order, in PEM format the certificate, key and any additional
	// intermediate CA certificate signing this certificate.
	//
	// Default: ""
	CertificateChain string

	// CertFile is a path of certificate file.
	// If you want to use TLS, you should enter this field or use "CertificateChain".
	//
	// Default : ""
	// NOTE : Deprecated. Use "CertificateChain" instead
	CertFile string

	// KeyFile is a path of certificate's private key.
	// If you want to use TLS, you should enter this field or use "CertificateChain".
	//
	// Default : ""
	// NOTE : Deprecated. Use "CertificateChain" instead
	CertKeyFile string

	// TLSMinVersion allows to set TLS minimum version.
	//
	// Default: tls.VersionTLS12
	// WARNING: TLS1.0 and TLS1.1 versions are not supported.
	TLSMinVersion uint16

	// Customizer provides a way to customize the *tls.Config.
	//
	// It uses an interface instead of a func to have predefined struct, with additional parameters.
	Customizer ServerCertificateCustomizer
}

var _ ServerTLSConfigProvider = &ServerCertificateProvider{}

// ProvideServerTLSConfig implements ServerTLSConfigProvider
//
// It may return nil, nil if no tls.Config can be provided and it not being an error.
func (cfg *ServerCertificateProvider) ProvideServerTLSConfig() (*tls.Config, error) {
	var tlsConfig *tls.Config

	if cfg.CertificateChain != "" {
		if block, _ := pem.Decode([]byte(cfg.CertificateChain)); block != nil {
			if cert, err := tls.X509KeyPair([]byte(cfg.CertificateChain), []byte(cfg.CertificateChain)); err != nil {
				return nil, fmt.Errorf("tls: cannot load TLS key pair from CertificateChain: %w", err)
			} else {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			}
		} else {
			if cert, err := tls.LoadX509KeyPair(cfg.CertificateChain, cfg.CertificateChain); err != nil {
				return nil, fmt.Errorf("tls: cannot load TLS key pair from CertificateChain: %w", err)
			} else {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			}
		}
	} else if cfg.CertFile != "" && cfg.CertKeyFile != "" {
		if cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.CertKeyFile); err != nil {
			return nil, fmt.Errorf("tls: cannot load TLS key pair from certFile=%q and keyFile=%q: %w", cfg.CertFile, cfg.CertKeyFile, err)
		} else {
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		}
	}
	if tlsConfig != nil {
		if cfg.TLSMinVersion == 0 {
			cfg.TLSMinVersion = tls.VersionTLS12
		}

		if cfg.TLSMinVersion != tls.VersionTLS12 && cfg.TLSMinVersion != tls.VersionTLS13 {
			return nil, fmt.Errorf("Unsupported TLS version, please use tls.VersionTLS12 or tls.VersionTLS13")
		}

		tlsConfig.MinVersion = cfg.TLSMinVersion
		if cfg.Customizer != nil {
			if err := cfg.Customizer.CustomizeServerCertificate(tlsConfig); err != nil {
				return nil, err
			}
		}

		return tlsConfig, nil
	}

	return nil, nil
}

// MTLSServerCertificateCustomizer is a struct implementing ServerCertificateCustomizer, to be used by ServerCertificateProvider.
type MTLSServerCertificateCustomizer struct {
	// ClientCertificate is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CA certificate.
	//
	// Default: ""
	ClientCertificate string
	clientCACert      *x509.Certificate
}

var _ ServerCertificateCustomizer = &MTLSServerCertificateCustomizer{}

// CustomizeServerCertificate implements ServerCertificateCustomizer.
//
// It parse the ClientCertificate, either a file path or its content, a PEM encoded CA certificate.
// It will add the certiticate to config.ClientCAs and set config.ClientAuth to tls.RequireAndVerifyClientCert
func (c *MTLSServerCertificateCustomizer) CustomizeServerCertificate(config *tls.Config) error {

	if c.ClientCertificate != "" {
		if block, _ := pem.Decode([]byte(c.ClientCertificate)); block != nil {
			if block.Type == "CERTIFICATE" {
				if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
					return fmt.Errorf("tls: cannot load client CA certificate: %w", err)
				} else {
					c.clientCACert = cert
				}
			} else {
				return fmt.Errorf("tls: cannot load client CA certificate: not a Certificate")
			}
		} else if file, err := os.ReadFile(filepath.Clean(c.ClientCertificate)); err != nil {
			return fmt.Errorf("tls: failed to read file from path: %w", err)
		} else if cert, err := x509.ParseCertificate(file); err != nil {
			return fmt.Errorf("tls: cannot load client CA certificate from path=%q: %w", c.ClientCertificate, err)
		} else {
			c.clientCACert = cert
		}
	}

	if c.clientCACert != nil {
		if config.ClientCAs == nil {
			config.ClientCAs = x509.NewCertPool()
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs.AddCert(c.clientCACert)
	}
	return nil
}

// GetCACertificate provide a way to retrieve the configured ClientCAs certificate.
func (c *MTLSServerCertificateCustomizer) GetCACertificate() *x509.Certificate {
	return c.clientCACert
}

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
	TLSProvider ClientTLSConfigProvider

	// Default: 10 * time.Seconds
	FetchClientTimeout time.Duration
}

var _ ServerCertificateCustomizer = &MTLSWithCRLServerCertificateCustomizer{}

// CustomizeServerCertificate implements ServerCertificateCustomizer
// It uses MTLSServerCertificateCustomizer to first set up mTLS, but adds Certificate Revocation List support.
// The CRL can be provided, using a file path or its content). It can also be fetching from a provider URL
// or using the URL in the CA certificate.
func (c *MTLSWithCRLServerCertificateCustomizer) CustomizeServerCertificate(config *tls.Config) error {
	var clientCACert *x509.Certificate

	mtls := &MTLSServerCertificateCustomizer{
		ClientCertificate: c.ClientCertificate,
	}

	if err := mtls.CustomizeServerCertificate(config); err != nil {
		return err
	} else if clientCACert = mtls.GetCACertificate(); clientCACert == nil {
		return nil // NOTE Should it return an error
	}

	fetch_crl := func(dist string) ([]byte, error) {
		cc := NewClient()
		cc.SetTimeout(c.FetchClientTimeout)

		if distUrl, err := url.Parse(dist); err != nil {
			return []byte{}, err
		} else if !slices.Contains([]string{"http", "https"}, distUrl.Scheme) {
			return []byte{}, fmt.Errorf("tls: CRL fetching client: wrong scheme=%q, only 'http' or 'https' is supported", distUrl.Scheme)
		} else if distUrl.Scheme == "https" {
			cc.SetTLSProvider(c.TLSProvider)
		}
		if resp, err := cc.Get(dist); err != nil {
			return []byte{}, fmt.Errorf("tls: unable to fetch certificate revocation list from url=%q: %w", dist, err)
		} else if block, _ := pem.Decode([]byte(resp.Body())); block != nil && block.Type == "X509 CRL" {
			return block.Bytes, nil
		} else {
			return []byte{}, fmt.Errorf("tls: unable to parse PEM CRL from url=%q", dist)
		}
	}

	if c.FetchClientTimeout == 0 {
		c.FetchClientTimeout = 10 * time.Second
	}

	var clientCRL *x509.RevocationList
	var crlBytes []byte

	if c.RevocationList != "" {
		if block, _ := pem.Decode([]byte(c.RevocationList)); block != nil && block.Type == "X509 CRL" {
			crlBytes = block.Bytes
		} else if file, err := os.ReadFile(filepath.Clean(c.RevocationList)); err != nil {
			return fmt.Errorf("tls: failed to read CRL file from path=%q: %w", c.RevocationList, err)
		} else {
			crlBytes = file
		}
	}

	if c.FetchRevocationList {
		if c.RevocationListURL != "" {
			if file, err := fetch_crl(c.RevocationListURL); err != nil {
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
