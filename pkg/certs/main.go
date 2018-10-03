package certs

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"time"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

type Provider interface {
	Provision(host string, validFrom string, validFor time.Duration, isCA bool, rsaBits int, ecdsaCurve string) (KeyPair, error)
	Deprovision(host string) error
}

type ProviderConfig struct {
	Kind       string            `json:"kind"`
	Url        string            `json:"url"`
	Bits       int               `json:"bits"`
	Username   string            `json:"username"`
	Password   string            `json:"password"`
	Realm      string            `json:"realm"`
	Ca_trust   bool              `json:"ca_trust"`
	Attributes map[string]string `json:"attrs"`
}

type ProviderAttrsConfig struct {
	CN           string `json:"cn"`
	Country      string `json:"country"`
	Province     string `json:"province"`
	Locality     string `json:"locality"`
	Organization string `json:"organization"`
	OU           string `json:"ou"`
	Email        string `json:"email"`
}

type KeyPair struct {
	Cert   []byte
	Key    []byte
	Expiry time.Time
}

// Shared functions
func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) (*pem.Block, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}, nil
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, NewCertError("Unable to marshal ECDSA private key: " + err.Error())
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}, nil
	default:
		return nil, NewCertError("Ran out of possible options for PEM Block")
	}
}

func createCSR(host string, attrs map[string]string) ([]byte, error) {
	keyBytes, keyErr := rsa.GenerateKey(rand.Reader, 1024)
	if keyErr != nil {
		return nil, keyErr
	}

	emailAddress := attrs["email"]
	subj := pkix.Name{
		CommonName:         host,
		Country:            []string{attrs["country"]},
		Province:           []string{attrs["province"]},
		Locality:           []string{attrs["locality"]},
		Organization:       []string{attrs["organization"]},
		OrganizationalUnit: []string{attrs["ou"]},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(emailAddress),
				},
			},
		},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, csrErr := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if csrErr != nil {
		return nil, keyErr
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}), nil
}
