/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// package authority implements X509 certificate authority features
package authority

import (
	"crypto"
	"crypto/rsa"
	"io"
	"io/ioutil"
	"time"

	"github.com/gravitational/license/constants"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/gravitational/trace"
)

// TLSKeyPair is a pair with TLS private key and certificate
type TLSKeyPair struct {
	// KeyPEM is private key PEM encoded contents
	KeyPEM []byte
	// CertPEM is certificate PEM encoded contents
	CertPEM []byte
}

// NewTLSKeyPair returns a new TLSKeyPair with private key and certificate found
// at the provided paths
func NewTLSKeyPair(keyPath, certPath string) (*TLSKeyPair, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &TLSKeyPair{
		KeyPEM:  keyBytes,
		CertPEM: certBytes,
	}, nil
}

// GenerateSelfSignedCA generates self signed certificate authority
func GenerateSelfSignedCA(req csr.CertificateRequest) (*TLSKeyPair, error) {
	if req.KeyRequest == nil {
		req.KeyRequest = &csr.KeyRequest{
			A: constants.TLSKeyAlgo,
			S: constants.TLSKeySize,
		}
	}
	cert, _, key, err := initca.New(&req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &TLSKeyPair{
		KeyPEM:  key,
		CertPEM: cert,
	}, nil
}

// ProcessCSR processes CSR (certificate sign request) with given cert authority
func ProcessCSR(req signer.SignRequest, ttl time.Duration, certAuthority *TLSKeyPair) ([]byte, error) {
	s, err := getSigner(certAuthority, ttl)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cert, err := s.Sign(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return cert, nil
}

// GenerateCertificate generates a certificate/key pair signed by the provided CA,
// if privateKeyPEM is provided, uses the key instead of generating it
func GenerateCertificate(req csr.CertificateRequest, certAuthority *TLSKeyPair, privateKeyPEM []byte, validFor time.Duration) (*TLSKeyPair, error) {
	return GenerateCertificateWithExtensions(req, certAuthority, privateKeyPEM, validFor, nil)
}

// GenerateCertificateWithExtensions is like GenerateCertificate but allows to specify
// extensions to include into generated certificate
func GenerateCertificateWithExtensions(req csr.CertificateRequest, certAuthority *TLSKeyPair, privateKeyPEM []byte, validFor time.Duration, extensions []signer.Extension) (*TLSKeyPair, error) {
	s, err := getSigner(certAuthority, validFor)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	csrBytes, key, err := GenerateCSR(req, privateKeyPEM)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var cert []byte
	signRequest := signer.SignRequest{
		Subject: &signer.Subject{
			CN:    req.CN,
			Names: req.Names,
		},
		Request:    string(csrBytes),
		Hosts:      req.Hosts,
		Extensions: extensions,
	}

	cert, err = s.Sign(signRequest)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &TLSKeyPair{
		CertPEM: cert,
		KeyPEM:  key,
	}, nil
}

var defaultKeyRequest = &csr.KeyRequest{
	A: constants.TLSKeyAlgo,
	S: constants.TLSKeySize,
}

// GenerateCSR generates new certificate signing request for existing key if supplied
// or generates new private key otherwise
func GenerateCSR(req csr.CertificateRequest, privateKeyPEM []byte) (csrBytes []byte, key []byte, err error) {
	if len(privateKeyPEM) != 0 {
		existingKey, err := NewExistingKey(privateKeyPEM)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		csrBytes, err = csr.Generate(existingKey, &req)
		if err != nil {
			return nil, nil, trace.Wrap(err)
		}
		return csrBytes, privateKeyPEM, nil
	}
	generator := &csr.Generator{
		Validator: func(req *csr.CertificateRequest) error {
			return nil
		},
	}
	req.KeyRequest = defaultKeyRequest

	csrBytes, key, err = generator.ProcessRequest(&req)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	return csrBytes, key, nil
}

// getSigner returns signer from TLSKeyPair assuming that keypair is a valid X509 certificate authority
func getSigner(certAuthority *TLSKeyPair, validFor time.Duration) (signer.Signer, error) {
	cert, err := helpers.ParseCertificatePEM(certAuthority.CertPEM)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	key, err := helpers.ParsePrivateKeyPEM(certAuthority.KeyPEM)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	profile := config.DefaultConfig()

	// whitelist our custom extension where encoded license payload will go
	profile.ExtensionWhitelist = map[string]bool{
		constants.LicenseASN1ExtensionID.String(): true,
	}

	// the default profile has 1 year expiration time, override it if it was provided
	if validFor != 0 {
		profile.NotAfter = time.Now().Add(validFor).UTC()
	}

	// set "not before" in the past to alleviate skewed clock issues
	profile.NotBefore = time.Now().Add(-time.Hour).UTC()

	policy := &config.Signing{
		Default: profile,
	}

	return local.NewSigner(key, cert, signer.DefaultSigAlgo(key), policy)
}

// ExistingKey tells signer to use existing key instead
type ExistingKey struct {
	key *rsa.PrivateKey
}

func NewExistingKey(keyPEM []byte) (*ExistingKey, error) {
	key, err := helpers.ParsePrivateKeyPEMWithPassword(keyPEM, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	rkey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, trace.BadParameter("only RSA keys supported, got %T", key)
	}
	return &ExistingKey{key: rkey}, nil
}

// Public returns the public key of this existing private key
func (kr *ExistingKey) Public() crypto.PublicKey {
	return kr.key.Public()
}

// Sign signs digest with the existing private key
func (kr *ExistingKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return kr.key.Sign(rand, digest, opts)
}
