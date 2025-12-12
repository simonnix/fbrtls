package fbr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofiber/fiber/v3/client"
)

type ClientTLSConfigProvider interface {
	ProvideClientTLSConfig() (*tls.Config, error)
}

type Client struct {
	*client.Client
}

func NewClient() *Client {
	c := &Client{}
	c.Client = client.New()
	return c
}

func (c *Client) SetTLSProvider(provider ClientTLSConfigProvider) *Client {
	if provider != nil {
		if cfg, err := provider.ProvideClientTLSConfig(); cfg != nil && err == nil {
			c.Client.SetTLSConfig(cfg)
		}
	}
	return c
}

type ClientCertificateProvider struct {
	// CertificateChain is either a path to a file or the content of the file instead.
	//
	// It must contain, in order, in PEM format the certificate, key and any additional
	// intermediate CA certificate signing this certificate.
	//
	// Default: ""
	CertificateChain string

	// RootCertificate adds a root certificate (either a path or its content : a PEM encoded CA certificate)
	// to verify the server TLS certificate against.
	//
	// It will follow the certificate CA chain (ie. if the server present a certificate
	// and other intermediate CA certficate leading to this Root CA, it will be accepted).
	//
	// Default: ""
	RootCertificate string
}

func (p *ClientCertificateProvider) ProvideClientTLSConfig() (*tls.Config, error) {
	var tlsConfig *tls.Config

	if p.CertificateChain != "" {
		if block, _ := pem.Decode([]byte(p.CertificateChain)); block != nil {
			if cert, err := tls.X509KeyPair([]byte(p.CertificateChain), []byte(p.CertificateChain)); err != nil {
				return nil, fmt.Errorf("tls: cannot load TLS key pair from CertificateChain: %w", err)
			} else {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			}
		} else {
			if cert, err := tls.LoadX509KeyPair(p.CertificateChain, p.CertificateChain); err != nil {
				return nil, fmt.Errorf("tls: cannot load TLS key pair from CertificateChain: %w", err)
			} else {
				tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			}
		}
	}

	if p.RootCertificate != "" {
		if tlsConfig != nil {
			tlsConfig.RootCAs = x509.NewCertPool()
		} else {
			tlsConfig = &tls.Config{
				RootCAs: x509.NewCertPool(),
			}
		}
		if block, _ := pem.Decode([]byte(p.RootCertificate)); block != nil {
			tlsConfig.RootCAs.AppendCertsFromPEM([]byte(p.RootCertificate))
		} else if file, err := os.ReadFile(filepath.Clean(p.RootCertificate)); err == nil {
			tlsConfig.RootCAs.AppendCertsFromPEM(file)
		}
	}

	return tlsConfig, nil
}
