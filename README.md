# FBRTLS

A Fiber application to test TLS configuration and possible evolutions.

Primary developed to add reading certificate configuration from string instead of files,
it has evolved into testing different configuration options.

It showcase supports mTLS, CRL and CRL fetching, but using `fiber.App.Listener` for now.

Those evolutions needs to be ported to `fiber.App.Listen`.

## TL;DR

You need to test this :
- this project under Linux or similar
- Bash
- GNU Make
- OpenSSL
- Golang 1.25
- the local port 3000 and 3001 available

Call `make` to create the PKI certificates and revocation list, config file and build the project

```bash
make
```

Run the server from a term

1. Run the server from a term :
```bash
# TERM A
./cmd/fbrtls server --auth --crl --fetch
```

2. Run the client from a valid certificate in the server Certificate Revocation List (another terminal):
```bash
# TERM B
./cmd/fbrtls client
```

3. Run the client from a revoked certificate in the server Certificate Revocation List (another terminal):
```bash
# TERM B
./cmd/fbrtls client --revoked
```

### Add the path flags

Certificates are read from a config file, paths can be used too. Thoses are read from the same config file.

To test the path instead of string value, add the `--path` parameter to both the server and client.

1. Server :

```bash
# TERM A
./cmd/fbrtls server --auth --crl --fetch --path
```

2. Client :

```bash
# TERM B
./cmd/fbrtls client --path
```

3. Revoked Client :

```bash
# TERM B
./cmd/fbrtls client --path --revoked
```


## Test PKI

I developed a shell script named `eztestpki` with an OpenSSL config file to generate a test PKI.

This script can be used in a CI/CD environment as it can be used multiple time, it will test the certificate and
regenerate them if required.

I will release this separately and document it elsewhere.

I used [easy-rsa](https://github.com/OpenVPN/easy-rsa) a long time ago but it does not generate intermediate CA and I wanted to have that.
I was inspired by that, but in coding it for a CI/CD environment, not a user friendly environment.

### PKI Content

Using the `Makefile` default target a PKI will be generated inside the `/test_pki` folder.

It generate a Root CA (`cacert.pem`) and an Intermediate CA (`certs/intermediate/cacert.pem`) signed by the Root CA.

The Root CA must be interpreted as a browser valid CA. Most TLS certificate comes now from 

Under the Intermediate CA are :
- a "server" server certificate (`certs/intermediate/certs/server/`)
- a "client" client certificate (`certs/intermediate/certs/client/`)
- a "revoked" revoked client certificate (`certs/intermediate/certs/revoked/`)

A signed CRLv2 in PEM format for this Intermediate CA (`certs/intermediate/crl.pem`).

This Intermediate CA Certficate has its field [CRL Distribution Point](https://docs.openssl.org/3.5/man5/x509v3_config/#crl-distribution-points)
defined to http://localhost:3001/ .

### Validity

Root CA : 30 years
Intermediate CA : 20 years
All others : 10 years

## Proposed changed.

PS: Look up thoses changes in this code.

1. Add a 'CertificateChain' field, deprecate "CertFile" and "CertKeyFile"

Right now, we need two file paths to configure TLS server settings in ListenConfig (`CertFile` and `CertKeyFile`).

Not only those are file paths and we can't configure TLS server settings from strings (obtained from config files,
Hashicorp Vault or elsewhere) but only one could be used.

Both functions `tls.X509KeyPair(string, string)` (which load PEM certificate and key from string values) and 
`tls.LoadX509KeyPair(string, string)` (which load PEM certificate and key from string paths) can
be used with the same value in the two parameters.

The string or file must contain both the certificate and key and it will be loaded.

Actually it can contain after both the certificate and key additional intermediate certificates to be presented and
validate the certificate chain. It's what we're using here.

In this example the "client" knows the Root CA certificate and the "server" present its certificate
signed by the Intermediate CA and the Intermediate CA certificate which is signed by the Root CA certificate.

The Chain is valid.

2. Externalize tls.Config in ListenConfig

Actually, `fiber.App.Listen`, in v3-rc3, has two ways to have a tls.Config set :

- Use `fiber.ListenConfig` members `CertFile` and `CertKeyFile` to get a Certificate.
  It uses `tls.LoadX509KeyPair()` using paths to a certificate and key.
- Use `fiber.ListenConfig` member `AutoCertManager` to get a certificate from an ACME provider.

I propose to change that to a member point to an interface in `fiber.ListenConfig`.

```go
type ServerTLSConfigProvider interface {
	ProvideServerTLSConfig() (*tls.Config, error)
}

type ListenConfig struct {
  // Skipping all other fields
	TLSProvider ServerTLSConfigProvider
}
```

I provide in this code a `struct` implementing this interface for the first part (`CertFile` and `CertKeyFile`) :

```go
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
```

An `ACMECertificateProvider` can easily coded to externalize that too from `fiber.ListenConfig`.

3. Remove CertClientFile, TLSConfigFunc from ListenConfig: Use a Customizer in ServerCertificateProvider

Please look at the `ServerCertificateProvider` struct, there is a `Customizer ServerCertificateCustomizer` Field.

It correspond to an interface :

```go 
type ServerCertificateCustomizer interface {
	CustomizeServerCertificate(config *tls.Config) error
}
```

I added two struct implementing this interface.

`MTLSServerCertificateCustomizer` replicate the `CertClientFile` except it also accept a PEM string instead of only a file path.

```go
type MTLSServerCertificateCustomizer struct {

	// ClientCertificate is either a path to a file or the content of the file instead.
	// It must be a PEM encoded CA certificate.
	//
	// Default: ""
	ClientCertificate string
}
```

And `MTLSWithCRLServerCertificateCustomizer` which do like `MTLSServerCertificateCustomizer` but also check a Certificate Revocation List.

```go
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
```

NOTE: The CRL is verified in `tls.Config.VerifyPeerCertificate` after the connection is validated against the `ClientCertificate`.

4. Use a "TLSProvider" for client.

Fiber "Client" accept a `tls.Config` through a function and a bunch of Storage providers have a `tls.Config` field.

CRL fetching is sometimes recommanded to use only HTTP, no HTTPS.

Anyway `MTLSWithCRLServerCertificateCustomizer` has a field `TLSProvider` for an interface `ClientTLSConfigProvider`:

```go
type ClientTLSConfigProvider interface {
	ProvideClientTLSConfig() (*tls.Config, error)
}

```

Like for `ListenConfig` field `TLSProvider` I have a default implementation:

```go

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
```

My suggestion is to use this interface instead of `tls.Config` in all Storage implementation needing a `tls.Config`.

Also to add this to fiber Client :

```go
func (c *Client) SetTLSProvider(provider ClientTLSConfigProvider) *Client {
	if provider != nil {
		if cfg, err := provider.ProvideClientTLSConfig(); cfg != nil && err == nil {
			c.Client.SetTLSConfig(cfg)
		}
	}
	return c
}
```

Nobody wants to create tls.Config objects, unless it can be reusable code and not be limited to files;
