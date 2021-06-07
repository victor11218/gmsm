package ucapp4go

import (
	"github.com/roy19831015/gmsm/x509"
)

type CertificateXAttribute struct {
	SecretKeyX      *SecretKeyX
	X509Cert        *x509.Certificate
	CertChain       *x509.CertPool
	CRL             *x509.CertPool
	UserId          string
	EnvelopSymmType SymmType
	EmptyIV         bool
	CharSet         string
	IgnoreChain     bool
	IgnoreCRL       bool
	Pkcs1HashType   x509.Hash
	Pkcs7HashType   x509.Hash
}
