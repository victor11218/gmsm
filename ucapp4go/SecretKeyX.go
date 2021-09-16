package ucapp4go

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/roy19831015/gmsm/sm2"
	x5092 "github.com/roy19831015/gmsm/x509"
)

type SecretKeyX struct {
	KeyUsage      int
	KeyAlgorithm  AsymmAlgType
	Key           crypto.PrivateKey
	CharSet       string
	BuffLen       int
}

func SecretKeyXConstructorWithInterface(key crypto.PrivateKey) (*SecretKeyX, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return &SecretKeyX{
			KeyUsage:      0,
			Key:           key,
			CharSet:       "UTF-8",
			BuffLen:       1024 * 1024 * 1,
		}, nil
	case *sm2.PrivateKey, *ecdsa.PrivateKey:
		return &SecretKeyX{
			KeyUsage:      0,
			Key:           key,
			CharSet:       "UTF-8",
			BuffLen:       1024 * 1024 * 1,
		}, nil
	default:
		return nil, errors.New("invalid private key type")
	}
}

func SecretKeyXConstructorWithByteArray(pbSecretKeyDER []byte) (*SecretKeyX, error) {
	key, err := x509.ParsePKCS8PrivateKey(pbSecretKeyDER)
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *rsa.PrivateKey:
		return &SecretKeyX{
			KeyUsage:      0,
			Key:           key,
			CharSet:       "UTF-8",
			BuffLen:       1024 * 1024 * 1,
		}, nil
	case *sm2.PrivateKey, *ecdsa.PrivateKey:
		return &SecretKeyX{
			KeyUsage:      0,
			Key:           key,
			CharSet:       "UTF-8",
			BuffLen:       1024 * 1024 * 1,
		}, nil
	default:
		return nil, errors.New("invalid private key type")
	}
}

func (skeyx *SecretKeyX) PKCS1Sign(pbPlainData []byte, hash x5092.Hash) ([]byte, error) {
	return PKCS1SignByPriKey(pbPlainData, DefaultUID, skeyx.Key, hash)
}

func (skeyx *SecretKeyX) PrivateDecrypt(pbEncData []byte) ([]byte, error) {
	return PrivateKeyDecrypt(skeyx.Key, pbEncData)
}
