// This file is based on code from github.com/grimm-co/GOCSP-responder.
// Original Copyright (c) 2016 SMFS Inc. DBA GRIMM https://grimm-co.com
//
// # Modifications Copyright (c) 2025 Simon HUET
//
// Licensed under the MIT License.
// ---------------------------------------------------------
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package services

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/simonnix/fbrtls/pkg/fbr"

	"golang.org/x/crypto/ocsp"
)

const (
	StatusValid   = 'V'
	StatusRevoked = 'R'
	StatusExpired = 'E'
)

type OCSPConfig struct {
	fbr.ListenConfig
	IndexFile    string
	RespKeyFile  string
	RespCertFile string
	CaCertFile   string
	Strict       bool
}

type OCSPResponder struct {
	*fbr.App
	listen       string
	config       *OCSPConfig
	indexEntries []IndexEntry
	indexModTime time.Time
	caCert       *x509.Certificate
	respCert     *x509.Certificate
}

type IndexEntry struct {
	Status byte
	Serial *big.Int // wow I totally called it
	// revocation reason may need to be added
	IssueTime         time.Time
	RevocationTime    time.Time
	DistinguishedName string
}

func (o OCSPResponder) New(listen string, config *OCSPConfig) (*OCSPResponder, error) {
	o.listen = listen
	o.config = config
	o.indexModTime = time.Time{}
	o.App = fbr.NewApp()
	o.Use(logger.New())
	o.Post("/", o.Handle)
	cacert, err := parseCertFile(o.config.CaCertFile)
	if err != nil {
		return nil, err
	}
	respcert, err := parseCertFile(o.config.RespCertFile)
	if err != nil {
		return nil, err
	}

	o.caCert = cacert
	o.respCert = respcert
	return &o, nil
}

func (o *OCSPResponder) Handle(c fiber.Ctx) error {
	if o.config.Strict && c.Get("Content-Type") != "application/ocsp-request" {
		return c.SendStatus(fiber.StatusBadRequest)
	}

	c.Set("Content-Type", "application/ocsp-response")
	resp, err := o.Verify(c.Body())

	if err != nil {
		log.Print(err)
		return c.SendStatus(fiber.StatusBadRequest)
	}

	return c.Send(resp)
}

func (o *OCSPResponder) Verify(rawreq []byte) ([]byte, error) {

	var status int
	var revokedAt time.Time

	req, err := ocsp.ParseRequest(rawreq)
	if err != nil {
		return nil, err
	}

	//make sure the request is valid
	if err := o.verifyIssuer(req); err != nil {
		log.Println(err)
		return nil, err
	}

	// get the index entry, if it exists
	ent, err := o.getIndexEntry(req.SerialNumber)
	if err != nil {
		log.Println(err)
		status = ocsp.Unknown
	} else {
		log.Printf("Found entry %+v", ent)
		switch ent.Status {
		case StatusRevoked:
			log.Print("This certificate is revoked")
			status = ocsp.Revoked
			revokedAt = ent.RevocationTime
		case StatusValid:
			log.Print("This certificate is valid")
			status = ocsp.Good
		}
	}

	// parse key file
	// perhaps I should zero this out after use
	keyi, err := parseKeyFile(o.config.RespKeyFile)
	if err != nil {
		return nil, err
	}
	key, ok := keyi.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: Could not make key a signer")
	}

	// construct response template
	template := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      o.respCert,
		RevocationReason: ocsp.Unspecified,
		IssuerHash:       req.HashAlgorithm,
		RevokedAt:        revokedAt,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		//adding 1 day after the current date. This ocsp library sets the default date to epoch which makes ocsp clients freak out.
		NextUpdate: time.Now().AddDate(0, 0, 1).UTC(),
	}

	// make a response to return
	resp, err := ocsp.CreateResponse(o.caCert, o.respCert, template, key)
	if err != nil {
		return nil, err
	}

	return resp, err
}

func (o *OCSPResponder) verifyIssuer(req *ocsp.Request) error {
	h := req.HashAlgorithm.New()
	h.Write(o.caCert.RawSubject)
	if !bytes.Equal(h.Sum(nil), req.IssuerNameHash) {
		return errors.New("tls: Issuer name does not match")
	}
	h.Reset()
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(o.caCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		return err
	}
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	if !bytes.Equal(h.Sum(nil), req.IssuerKeyHash) {
		return errors.New("tls: Issuer key hash does not match")
	}
	return nil
}

// function to parse the index file
func (o *OCSPResponder) parseIndex() error {
	var t = "060102150405Z"
	finfo, err := os.Stat(o.config.IndexFile)
	if err == nil {
		// if the file modtime has changed, then reload the index file
		if finfo.ModTime().After(o.indexModTime) {
			o.indexModTime = finfo.ModTime()
			// clear index entries
			o.indexEntries = o.indexEntries[:0]
		} else {
			// the index has not changed. just return
			return nil
		}
	} else {
		return err
	}

	// open and parse the index file
	if file, err := os.Open(o.config.IndexFile); err == nil {
		//nolint:errcheck
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			var ie IndexEntry
			ln := strings.Fields(s.Text())
			ie.Status = []byte(ln[0])[0]
			ie.IssueTime, _ = time.Parse(t, ln[1])
			switch ie.Status {
			case StatusValid:
				ie.Serial, _ = new(big.Int).SetString(ln[2], 16)
				ie.DistinguishedName = ln[4]
				ie.RevocationTime = time.Time{} //doesn't matter
			case StatusRevoked:
				ie.Serial, _ = new(big.Int).SetString(ln[3], 16)
				ie.DistinguishedName = ln[5]
				ie.RevocationTime, _ = time.Parse(t, ln[2])
			default:
				continue
			}
			o.indexEntries = append(o.indexEntries, ie)
		}
	} else {
		return err
	}
	return nil
}

// updates the index if necessary and then searches for the given index in the
// index list
func (o *OCSPResponder) getIndexEntry(s *big.Int) (*IndexEntry, error) {
	log.Printf("Looking for serial 0x%x", s)
	if err := o.parseIndex(); err != nil {
		return nil, err
	}
	for _, entry := range o.indexEntries {
		if entry.Serial.Cmp(s) == 0 {
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("tls: Serial 0x%x not found", s)
}

// parses a pem encoded x509 certificate
func parseCertFile(filename string) (*x509.Certificate, error) {
	ct, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(ct)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// parses a PEM encoded PKCS8 private key (RSA only)
func parseKeyFile(filename string) (any, error) {
	kt, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(kt)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func (o *OCSPResponder) Run(wg *sync.WaitGroup) {
	wg.Go(func() {
		//nolint:errcheck
		o.Listen(o.listen, o.config.ListenConfig)
	})
	time.Sleep(200 * time.Millisecond)
}
