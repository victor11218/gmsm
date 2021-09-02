package ucapp4go

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	x5092 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/roy19831015/gmsm/sm2"
	"github.com/roy19831015/gmsm/x509"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

type CertificateX struct {
	CertificateXAttribute
}

func CertificateXConstructorWithByteArray(pbCertDER []byte, pbSecretKeyDER []byte) (*CertificateX, error) {
	var (
		err   error
		cx509 *x509.Certificate
		sxkey *SecretKeyX
	)

	if pbCertDER != nil && len(pbCertDER) > 0 {
		cx509, err = x509.ParseCertificate(pbCertDER)
		if err != nil {
			return nil, err
		}
	}

	if pbSecretKeyDER != nil && len(pbSecretKeyDER) > 0 {
		sxkey, err = SecretKeyXConstructorWithByteArray(pbSecretKeyDER)
		if err != nil {
			return nil, err
		}
	}
	return &CertificateX{CertificateXAttribute{
		SecretKeyX:      sxkey,
		X509Cert:        cx509,
		CertChain:       nil,
		CRL:             nil,
		UserId:          "1234567812345678",
		EnvelopSymmType: 0,
		EmptyIV:         true,
		CharSet:         "",
		IgnoreChain:     true,
		IgnoreCRL:       true,
		Pkcs1HashType:   x509.Hash(0),
		Pkcs7HashType:   x509.Hash(0),
	}}, nil
}

func CertificateXConstructorWithInterface(cert *x509.Certificate, priKey crypto.PrivateKey) (*CertificateX, error) {
	var skey *SecretKeyX
	var err error
	if priKey != nil {
		skey, err = SecretKeyXConstructorWithInterface(priKey)
		if err != nil {
			return nil, err
		}
	}
	return &CertificateX{CertificateXAttribute{
		SecretKeyX:      skey,
		X509Cert:        cert,
		CertChain:       nil,
		CRL:             nil,
		UserId:          "1234567812345678",
		EnvelopSymmType: 0,
		EmptyIV:         true,
		CharSet:         "",
		IgnoreChain:     true,
		IgnoreCRL:       true,
		Pkcs1HashType:   0,
		Pkcs7HashType:   0,
	}}, nil
}

func CertificateXConstructorWithReader(readerCertBase64 io.Reader, readerSecretKeyBase64 io.Reader) (*CertificateX, error) {
	var pbCertDER, pbSecretKeyDER, all []byte
	var err error
	if readerCertBase64 != nil {
		all, err = ioutil.ReadAll(readerCertBase64)
		if err != nil {
			return nil, err
		}
		if len(all) <= 0 {
			return nil, errors.New("empty reader in 'readerCertBase64'")
		}
		if all[0] == byte('M') {
			pbCertDER, _ = Base64Decode(string(all))
		} else if bytes.Equal(all[0:27], []byte("-----BEGIN CERTIFICATE-----")) {
			str := strings.ReplaceAll(strings.ReplaceAll(string(all), "-----BEGIN CERTIFICATE-----", ""), "-----END CERTIFICATE-----", "")
			pbCertDER, _ = Base64Decode(str)
		} else {
			pbCertDER = all
		}
	}
	if readerSecretKeyBase64 != nil {
		pbSecretKeyDER, err = ioutil.ReadAll(readerSecretKeyBase64)
		if err != nil {
			return nil, err
		}
		if len(pbSecretKeyDER) <= 0 {
			return nil, errors.New("empty reader in 'readerSecretKeyBase64'")
		}
	}
	return CertificateXConstructorWithByteArray(pbCertDER, pbSecretKeyDER)
}

func CertificateXConstructorWithBase64String(strCertBase64 string, strSecretKeyBase64 string) (*CertificateX, error) {
	pbCertDER, _ := Base64Decode(strCertBase64)
	pbSecretKeyDER, _ := Base64Decode(strSecretKeyBase64)
	return CertificateXConstructorWithByteArray(pbCertDER, pbSecretKeyDER)
}

func (certx *CertificateX) PKCS1Sign(pbPlainData []byte) ([]byte, error) {
	return certx.SecretKeyX.PKCS1Sign(pbPlainData)
}

func (certx *CertificateX) PKCS1Verify(pbPlainData []byte, pbSignData []byte) error {
	return PKCS1VerifyByPubKey(pbPlainData, pbSignData, DefaultUID, certx.X509Cert.PublicKey, certx.Pkcs1HashType)
}

func (certx *CertificateX) PKCS7Sign(pbPlainData []byte, isDetach bool) ([]byte, error) {
	pkcs1SignData, err := PKCS1SignByPriKey(pbPlainData, DefaultUID, certx.SecretKeyX.Key, certx.Pkcs7HashType)
	if err != nil {
		return nil, err
	}
	var data []byte
	if isDetach {
		data = nil
	} else {
		data = pbPlainData
	}
	signData, err := x509.NewPKCS7SignedData(data, pkcs1SignData, certx.Pkcs7HashType, certx.X509Cert)
	if err != nil {
		return nil, err
	}
	return signData.Finish()
}

func (certx *CertificateX) PKCS7Verify(pbPlainData []byte, pbSignData []byte) error {
	p7, err := x509.ParsePKCS7(pbSignData)
	if err != nil {
		return err
	}
	return p7.VerifyWithPlainData(pbPlainData, nil, nil, nil)
}

func (certx *CertificateX) PublicEncrypt(pbPlainData []byte) ([]byte, error) {
	return PublicKeyEncrypt(certx.X509Cert.PublicKey, pbPlainData)
}

func (certx *CertificateX) PrivateDecrypt(pbEncData []byte) ([]byte, error) {
	return certx.SecretKeyX.PrivateDecrypt(pbEncData)
}

func (certx *CertificateX) EnvSeal(pbPlainData []byte) ([]byte, error) {
	return x509.PKCS7Encrypt(pbPlainData, []*x509.Certificate{certx.X509Cert}, GetEncryptionAlgorithmBySymmType(certx.EnvelopSymmType))
}

func (certx *CertificateX) EnvOpen(pbEnvData []byte) ([]byte, error) {
	p7, err := x509.ParsePKCS7(pbEnvData)
	if err != nil {
		return nil, err
	}
	return p7.Decrypt(certx.X509Cert, certx.SecretKeyX.Key)
}

func (certx *CertificateX) GetExtension(oid string) ([]byte, error) {
	for _, ext := range certx.X509Cert.Extensions {
		if ext.Id.String() == oid {
			return ext.Value, nil
		}
	}
	return nil, errors.New(`have no extension with the oid name : "` + oid + `"`)
}

func (certx *CertificateX) GetExtensionString(oid string) (string, error) {
	oidv, err := certx.GetExtension(oid)
	if err != nil {
		return "", err
	}
	var ret string
	_, err = asn1.Unmarshal(oidv, &ret)
	if err != nil {
		return HexEncode(oidv)
	}
	return ret, nil
}

func (certx *CertificateX) GetSubject() string {
	return certx.X509Cert.Subject.String()
}

func (certx *CertificateX) GetCN() string {
	return certx.X509Cert.Subject.CommonName
}

func (certx *CertificateX) GetContent() string {
	ret, err := Base64Encode(certx.X509Cert.Raw)
	if err != nil {
		return ""
	}
	return ret
}

func (certx *CertificateX) GetSerialNumber() string {
	return certx.X509Cert.SerialNumber.Text(16)
}

func (certx *CertificateX) GetIssuer() string {
	return certx.X509Cert.Issuer.String()
}

func (certx *CertificateX) GetVersion() string {
	return strconv.Itoa(certx.X509Cert.Version)
}

func (certx *CertificateX) GetSignatureAlgorithm() string {
	return certx.X509Cert.SignatureAlgorithm.String()
}

func (certx *CertificateX) GetNotBeforeTime() time.Time {
	return certx.X509Cert.NotBefore
}

func (certx *CertificateX) GetNotAfterTime() time.Time {
	return certx.X509Cert.NotAfter
}

func (certx *CertificateX) GetNotBeforeTimestamp() string {
	return strconv.FormatInt(certx.X509Cert.NotBefore.Unix(), 10)
}

func (certx *CertificateX) GetNotAfterTimestamp() string {
	return strconv.FormatInt(certx.X509Cert.NotAfter.Unix(), 10)
}

func (certx *CertificateX) GetNotBeforeSystemTime() string {
	return certx.X509Cert.NotBefore.Format("2006-01-02 15:04:05")
}

func (certx *CertificateX) GetNotAfterSystemTime() string {
	return certx.X509Cert.NotAfter.Format("2006-01-02 15:04:05")
}

func (certx *CertificateX) GetAlgorithm() string {
	var ret string
	switch certx.X509Cert.PublicKeyAlgorithm {
	case x509.RSA:
		ret = "RSA"
	case x509.DSA:
		ret = "DSA"
	case x509.ECDSA:
		ret = "SM2"
	case x509.SM2:
		ret = "SM2"
	default:
		ret = "UNKNOWN"
	}
	return ret
}

func (certx *CertificateX) GetKeybits() int {
	var ret int
	switch certx.X509Cert.PublicKeyAlgorithm {
	case x509.RSA:
		ret = certx.X509Cert.PublicKey.(*rsa.PublicKey).Size() * 8
	case x509.DSA:
		ret = 256
	case x509.ECDSA:
		ret = 256
	case x509.SM2:
		ret = 256
	default:
		ret = 0
	}
	return ret
}

func (certx *CertificateX) GetKeyUsage() int {
	ret := 0
	if (certx.X509Cert.KeyUsage & x509.KeyUsageDigitalSignature) == x509.KeyUsageDigitalSignature {
		ret |= 1
	}
	if (certx.X509Cert.KeyUsage & x509.KeyUsageKeyEncipherment) == x509.KeyUsageKeyEncipherment {
		ret |= 2
	}
	return ret
}

func (certx *CertificateX) GetPubKeyB64() (string, error) {
	var derPub []byte
	var err error
	switch certx.X509Cert.PublicKeyAlgorithm {
	case x509.RSA:
		derPub, err = x509.MarshalPKIXPublicKey(certx.X509Cert.PublicKey)
	case x509.ECDSA:
		derPub, err = x509.MarshalSm2PublicKey(&sm2.PublicKey{
			Curve: certx.X509Cert.PublicKey.(*ecdsa.PublicKey).Curve,
			X:     certx.X509Cert.PublicKey.(*ecdsa.PublicKey).X,
			Y:     certx.X509Cert.PublicKey.(*ecdsa.PublicKey).Y,
		})
	case x509.SM2:
		derPub, err = x509.MarshalSm2PublicKey(certx.X509Cert.PublicKey.(*sm2.PublicKey))
	default:
		return "", errors.New("invalid key type")
	}
	if err != nil {
		return "", err
	}
	return Base64Encode(derPub)
}

func (certx *CertificateX) GetPriKeyB64() (string, error) {
	var derPri []byte
	var err error
	switch certx.X509Cert.PublicKeyAlgorithm {
	case x509.RSA:
		derPri, err = x5092.MarshalPKCS8PrivateKey(certx.SecretKeyX.Key)
	case x509.ECDSA:
		bint := certx.SecretKeyX.Key.(*ecdsa.PrivateKey).D
		println(bint)
		derPri, err = x509.MarshalSm2PrivateKey(&sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: certx.SecretKeyX.Key.(*ecdsa.PrivateKey).Curve,
				X:     certx.SecretKeyX.Key.(*ecdsa.PrivateKey).PublicKey.X,
				Y:     certx.SecretKeyX.Key.(*ecdsa.PrivateKey).PublicKey.Y,
			},
			D: certx.SecretKeyX.Key.(*ecdsa.PrivateKey).D,
		}, nil)
	case x509.SM2:
		derPri, err = x509.MarshalSm2PrivateKey(certx.SecretKeyX.Key.(*sm2.PrivateKey), nil)
	default:
		return "", errors.New("invalid key type")
	}
	if err != nil {
		return "", err
	}
	return Base64Encode(derPri)
}

func (certx *CertificateX) GetSubjectUniqueId() (string, error) {
	var oidSUid asn1.ObjectIdentifier
	oidSUid = OidExtensionSubjectKeyId
	oidv, err := certx.GetExtension(oidSUid.String())
	if err != nil {
		return "", err
	}
	var ret []byte
	_, err = asn1.Unmarshal(oidv, &ret)
	if err != nil {
		return "", err
	}
	return HexEncode(ret)
}

func (certx *CertificateX) GetIssuerUniqueId() (string, error) {
	var oidIUid asn1.ObjectIdentifier
	oidIUid = OidExtensionAuthorityKeyId
	oidv, err := certx.GetExtension(oidIUid.String())
	if err != nil {
		return "", err
	}
	var ret struct {
		asn1.RawValue `asn1:"tag:0"`
	}
	_, err = asn1.Unmarshal(oidv, &ret)
	if err != nil {
		return "", err
	}
	return HexEncode(ret.Bytes)
}

func (certx *CertificateX) GetX509() (*x509.Certificate, error) {
	return certx.X509Cert, nil
}

func (certx *CertificateX) GetPkcs1HashType() x509.Hash {
	return certx.Pkcs1HashType
}

func (certx *CertificateX) CreateCRL(rand io.Reader, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) (crlBytes []byte, err error) {
	return certx.X509Cert.CreateCRL(rand, certx.SecretKeyX.Key, revokedCerts, now, expiry)
}

func (certx *CertificateX) GetP7B() ([]byte, error) {
	certp := []*x509.Certificate{certx.X509Cert}
	b, err := x509.NewP7B(certp)
	if err != nil {
		return nil, err
	}
	return b.DirectFinish()
}

type SM2EnvelopedKey struct {
	SymmAlgID              pkix.AlgorithmIdentifier
	SymmEncryptedKey       sm2.SM2Cipher
	SM2PublicKey           []byte
	SM2EncryptedPrivateKey []byte
}

func (certx *CertificateX) EncryptExchangeKeyWithSignCert(encodedPlainKey []byte) (string, error) {
	eci, r, err := x509.ExchangeKeyEncrypt(encodedPlainKey, certx.X509Cert, GetEncryptionAlgorithmBySymmType(certx.EnvelopSymmType))
	if err != nil {
		return "", err
	}
	switch certx.X509Cert.PublicKeyAlgorithm {
	case x509.RSA:
		encodedEc, err := Base64Encode(eci.EncryptedContent.Bytes)
		if err != nil {
			return "", err
		}
		encodedEk, err := Base64Encode(r.EncryptedKey)
		return encodedEk + "!!!" + encodedEc, nil
	case x509.ECDSA:
		pub := &sm2.PublicKey{
			Curve: certx.X509Cert.PublicKey.(*ecdsa.PublicKey).Curve,
			X:     certx.X509Cert.PublicKey.(*ecdsa.PublicKey).X,
			Y:     certx.X509Cert.PublicKey.(*ecdsa.PublicKey).Y,
		}
		var sm2cipher sm2.SM2Cipher
		_, err := asn1.Unmarshal(r.EncryptedKey, &sm2cipher)
		if err != nil {
			return "", err
		}
		sm2EnvelopedKey := SM2EnvelopedKey{
			SymmAlgID:              eci.ContentEncryptionAlgorithm,
			SymmEncryptedKey:       sm2cipher,
			SM2PublicKey:           sm2.Compress(pub),
			SM2EncryptedPrivateKey: eci.EncryptedContent.Bytes,
		}
		out, err := asn1.Marshal(sm2EnvelopedKey)
		if err != nil {
			return "", err
		}
		return Base64Encode(out)
	case x509.SM2:
		var sm2cipher sm2.SM2Cipher
		_, err := asn1.Unmarshal(r.EncryptedKey, &sm2cipher)
		if err != nil {
			return "", err
		}
		sm2EnvelopedKey := SM2EnvelopedKey{
			SymmAlgID:              eci.ContentEncryptionAlgorithm,
			SymmEncryptedKey:       sm2cipher,
			SM2PublicKey:           sm2.Compress(certx.X509Cert.PublicKey.(*sm2.PublicKey)),
			SM2EncryptedPrivateKey: eci.EncryptedContent.Bytes,
		}
		out, err := asn1.Marshal(sm2EnvelopedKey)
		if err != nil {
			return "", err
		}
		return Base64Encode(out)
	default:
		return "", errors.New("invalid key type")
	}
}
