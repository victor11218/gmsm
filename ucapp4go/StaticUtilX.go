package ucapp4go

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	x5092 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/victor11218/gmsm/pkcs12"
	"github.com/victor11218/gmsm/sm2"
	"github.com/victor11218/gmsm/x509"
)

func Base64Encode(pbData []byte) (string, error) {
	return base64.StdEncoding.EncodeToString(pbData), nil
}

func Base64Decode(strBase64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strBase64)
}

func UrlBase64Encode(pbData []byte) (string, error) {
	return base64.URLEncoding.EncodeToString(pbData), nil
}

func UrlBase64Decode(strBase64 string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(strBase64)
}

func HexEncode(pbData []byte) (string, error) {
	return hex.EncodeToString(pbData), nil
}

func HexDecode(strHex string) ([]byte, error) {
	return hex.DecodeString(strHex)
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func PKCS1VerifyByPubKey(pbPlainData []byte, pbSignData []byte, userID []byte, pubKey crypto.PublicKey, hashType x509.Hash) error {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		pub := pubKey.(*rsa.PublicKey)
		var hashed []byte
		var hashHandle = hashType.New()
		writtenLen, err := hashHandle.Write(pbPlainData)
		if err != nil {
			return err
		}
		if writtenLen != len(pbPlainData) {
			return errors.New("stream write error in hash process")
		}
		hashed = hashHandle.Sum(nil)
		return rsa.VerifyPKCS1v15(pub, hashType.HashFunc(), hashed, pbSignData)
	case *sm2.PublicKey:
		pub := pubKey.(sm2.PublicKey)
		if pub.Verify(pbPlainData, pbSignData) {
			return nil
		} else {
			return errors.New("sm2 verify result is false")
		}
	case *ecdsa.PublicKey:
		pub := sm2.PublicKey{
			Curve: pubKey.(*ecdsa.PublicKey).Curve,
			X:     pubKey.(*ecdsa.PublicKey).X,
			Y:     pubKey.(*ecdsa.PublicKey).Y,
		}
		if pub.Verify(pbPlainData, pbSignData) {
			return nil
		} else {
			return errors.New("sm2 verify result is false")
		}
	default:
		return errors.New("invalid public key type")
	}
}

func PKCS1SignByPriKey(pbPlainData []byte, userID []byte, priKey crypto.PrivateKey, hashType x509.Hash) ([]byte, error) {
	var signed []byte
	switch priKey.(type) {
	case *rsa.PrivateKey:
		p1Key := priKey.(*rsa.PrivateKey)
		var hashed []byte
		var hashHandle = hashType.New()
		writtenLen, err := hashHandle.Write(pbPlainData)
		if err != nil {
			return nil, err
		}
		if writtenLen != len(pbPlainData) {
			return nil, errors.New("stream write error in hash process")
		}
		hashed = hashHandle.Sum(nil)

		signed, err = rsa.SignPKCS1v15(rand.Reader, p1Key, hashType.HashFunc(), hashed)
		if err != nil {
			return nil, err
		}
	case *sm2.PrivateKey:
		p1Key := priKey.(*sm2.PrivateKey)
		r, s, err := sm2.Sm2Sign(p1Key, pbPlainData, userID, rand.Reader)
		if err != nil {
			return nil, err
		}
		signed, err = sm2.SignDigitToSignData(r, s)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PrivateKey:
		p1Key := sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: priKey.(*ecdsa.PrivateKey).Curve,
				X:     priKey.(*ecdsa.PrivateKey).X,
				Y:     priKey.(*ecdsa.PrivateKey).Y,
			},
			D: priKey.(*ecdsa.PrivateKey).D,
		}
		r, s, err := sm2.Sm2Sign(&p1Key, pbPlainData, userID, rand.Reader)
		if err != nil {
			return nil, err
		}
		signed, err = sm2.SignDigitToSignData(r, s)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid private key type")
	}
	return signed, nil
}

func PKCS12ParseCert(strP12Base64 string, strPin string) (*CertificateX, error) {
	var err error
	pbP12, err := Base64Decode(strP12Base64)
	if err != nil {
		return nil, err
	}
	priKey, cert, err := pkcs12.DecodeX(pbP12, strPin)
	if err != nil {
		return nil, err
	}
	return CertificateXConstructorWithInterface(cert, priKey)
}

func PublicKeyEncrypt(pubKey crypto.PublicKey, plainData []byte) ([]byte, error) {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		pub := pubKey.(*rsa.PublicKey)
		return rsa.EncryptPKCS1v15(rand.Reader, pub, plainData)
	case *sm2.PublicKey:
		pub := pubKey.(*sm2.PublicKey)
		return sm2.EncryptAsn1(pub, plainData, rand.Reader)
	case *ecdsa.PublicKey:
		pub := &sm2.PublicKey{
			Curve: pubKey.(*ecdsa.PublicKey).Curve,
			X:     pubKey.(*ecdsa.PublicKey).X,
			Y:     pubKey.(*ecdsa.PublicKey).Y,
		}
		return sm2.EncryptAsn1(pub, plainData, rand.Reader)
	default:
		return nil, errors.New("invalid public key type")
	}
}

func PrivateKeyDecrypt(priKey crypto.PrivateKey, pbEncData []byte) ([]byte, error) {
	switch priKey.(type) {
	case *rsa.PrivateKey:
		pri := priKey.(*rsa.PrivateKey)
		return rsa.DecryptPKCS1v15(rand.Reader, pri, pbEncData)
	case *sm2.PrivateKey:
		pri := priKey.(*sm2.PrivateKey)
		return sm2.DecryptAsn1(pri, pbEncData)
	case *ecdsa.PrivateKey:
		pri := &sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: priKey.(*ecdsa.PrivateKey).Curve,
				X:     priKey.(*ecdsa.PrivateKey).X,
				Y:     priKey.(*ecdsa.PrivateKey).Y,
			},
			D: priKey.(*ecdsa.PrivateKey).D,
		}
		return sm2.DecryptAsn1(pri, pbEncData)
	default:
		return nil, errors.New("invalid public key type")
	}
}

func GenerateKeyPair(asymmType AsymmAlgType, keyBitLen int) (crypto.PrivateKey, error) {
	var priv crypto.PrivateKey
	var err error
	switch asymmType {
	case SM2:
		priv, err = sm2.GenerateKey(rand.Reader) // 生成密钥对
		if err != nil {
			return nil, err
		}
	case RSA:
		priv, err = rsa.GenerateKey(rand.Reader, keyBitLen) // 生成密钥对
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid key type")
	}
	return priv, nil
}

//CreatePKCS10Request
func CreatePKCS10Request(asymmType AsymmAlgType, keyBitLen int) (crypto.PrivateKey, *x509.P10CertificateRequest, error) {
	var pri crypto.PrivateKey
	var sigAlg x509.SignatureAlgorithm
	var templateReq x509.CertificateRequest
	var p10req *x509.P10CertificateRequest
	var err error
	pri, err = GenerateKeyPair(asymmType, keyBitLen)
	if err != nil {
		return nil, nil, err
	}
	switch asymmType {
	case SM2:
		sigAlg = x509.SM2WithSM3
		templateReq = x509.CertificateRequest{
			Subject: pkix.Name{
				Country:      []string{"CN"},
				Organization: []string{"ORG"},
				Locality:     []string{"Wuhan"},
				Province:     []string{"HuBei"},
				CommonName:   "TEST123",
			},
			SignatureAlgorithm: sigAlg,
		}
		p10req, err = x509.CreateP10CertificateRequest(rand.Reader, &templateReq, pri.(*sm2.PrivateKey))
	case RSA:
		sigAlg = x509.SHA256WithRSA
		templateReq = x509.CertificateRequest{
			Subject: pkix.Name{
				Country:      []string{"CN"},
				Organization: []string{"ORG"},
				Locality:     []string{"Wuhan"},
				Province:     []string{"HuBei"},
				CommonName:   "TEST123",
			},
			SignatureAlgorithm: sigAlg,
		}
		p10req, err = x509.CreateP10CertificateRequest(rand.Reader, &templateReq, pri.(*rsa.PrivateKey))
	default:
		return nil, nil, errors.New("invalid key type")
	}
	return pri, p10req, nil
}

//CreatePKCS10RequestString
//return 4 values present as:
//pub string
//pri string
//p10req string
//err error
func CreatePKCS10RequestString(asymmType AsymmAlgType, keyBitLen int) (string, string, string, error) {
	var pri crypto.PrivateKey
	var sigAlg x509.SignatureAlgorithm
	var templateReq x509.CertificateRequest
	var derP10, derPri, derPub []byte
	var err error
	pri, err = GenerateKeyPair(asymmType, keyBitLen)
	if err != nil {
		return "", "", "", err
	}
	switch asymmType {
	case SM2:
		sigAlg = x509.SM2WithSM3
		templateReq = x509.CertificateRequest{
			Subject: pkix.Name{
				Country:      []string{"CN"},
				Organization: []string{"ORG"},
				Locality:     []string{"Wuhan"},
				Province:     []string{"HuBei"},
				CommonName:   "TEST123",
			},
			SignatureAlgorithm: sigAlg,
		}
		derP10, err = x509.CreateCertificateRequest(rand.Reader, &templateReq, pri.(*sm2.PrivateKey))
		derPri, err = x509.MarshalSm2PrivateKey(pri.(*sm2.PrivateKey), nil)
		derPub, err = x509.MarshalSm2PublicKey(&pri.(*sm2.PrivateKey).PublicKey)
	case RSA:
		sigAlg = x509.SHA256WithRSA
		templateReq = x509.CertificateRequest{
			Subject: pkix.Name{
				Country:      []string{"CN"},
				Organization: []string{"ORG"},
				Locality:     []string{"Wuhan"},
				Province:     []string{"HuBei"},
				CommonName:   "TEST123",
			},
			SignatureAlgorithm: sigAlg,
		}
		derP10, err = x509.CreateCertificateRequest(rand.Reader, &templateReq, pri.(*rsa.PrivateKey))
		derPri, err = x5092.MarshalPKCS8PrivateKey(pri.(*rsa.PrivateKey))
		derPub, err = x509.MarshalPKIXPublicKey(&pri.(*rsa.PrivateKey).PublicKey)
	default:
		return "", "", "", errors.New("invalid key type")
	}
	strP10Base64, err := Base64Encode(derP10)
	if err != nil {
		return "", "", "", err
	}
	strPubBase64, err := Base64Encode(derPub)
	if err != nil {
		return "", "", "", err
	}
	strPriBase64, err := Base64Encode(derPri)
	if err != nil {
		return "", "", "", err
	}
	return strPubBase64, strPriBase64, strP10Base64, nil
}

func CombineToPKCS12(certBase64 string, certPrivateKey string, pin string, caCerts []*x5092.Certificate) ([]byte, error) {
	pbPrivateKey, err := Base64Decode(certPrivateKey)
	if err != nil {
		return nil, err
	}

	pbCert, err := Base64Decode(certBase64)
	if err != nil {
		return nil, err
	}
	pbCert, err = Base64Decode(certBase64)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pbCert)

	var pri crypto.PrivateKey
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		pri, err = x509.ParsePKCS8PrivateKey(x509.RSA, pbPrivateKey, nil)
		return pkcs12.Encode(pri, cert, caCerts, pin)
	case x509.ECDSA, x509.SM2:
		pri, err = x509.ParsePKCS8PrivateKey(x509.SM2, pbPrivateKey, nil)
		return pkcs12.Encode(pri, cert, caCerts, pin)
	default:
		return nil, errors.New("invalid key type")
	}
}

func GetEncryptionAlgorithmBySymmType(symmType SymmType) int {
	switch symmType {
	case AES256:
		return x509.EncryptionAlgorithmAES256
	case SM4:
		return x509.EncryptionAlgorithmSM4
	case DES:
		return x509.EncryptionAlgorithmDESCBC
	case DESede:
		return x509.EncryptionAlgorithmDESede
	case SM1:
		return x509.EncryptionAlgorithmSM1
	case RC4:
		return x509.EncryptionAlgorithmRC4
	case AES256EmptyIV:
		return x509.EncryptionAlgorithmAES256EmptyIV
	default:
		return -1
	}
}

func GetPlainTextFromP7SignedData(pbSignData []byte) ([]byte, error) {
	p7, err := x509.ParsePKCS7(pbSignData)
	if err != nil {
		return nil, err
	}
	if p7.Content == nil || len(p7.Content) == 0 {
		return nil, errors.New("detached signature doesn't have plain content")
	} else {
		return p7.Content, nil
	}
}

func GetIssuerFromP7SignedData(pbSignData []byte) ([]string, error) {
	p7, err := x509.ParsePKCS7(pbSignData)
	if err != nil {
		return nil, err
	}
	retArr := make([]string, 0)
	for _, signer := range p7.Signers {
		var issuer pkix.Name
		_, err = asn1.Unmarshal(signer.IssuerAndSerialNumber.IssuerName.Bytes, &issuer)
		if err != nil {
			continue
		}
		retArr = append(retArr, issuer.String())
	}
	return retArr, nil
}

func GetSeriNoFromP7SignedData(pbSignData []byte) ([]string, error) {
	p7, err := x509.ParsePKCS7(pbSignData)
	if err != nil {
		return nil, err
	}
	retArr := make([]string, 0)
	for _, signer := range p7.Signers {
		sn := signer.IssuerAndSerialNumber.SerialNumber.Text(16)
		if err != nil {
			continue
		}
		retArr = append(retArr, sn)
	}
	return retArr, nil
}

func GetCertFromP7SignedData(pbSignData []byte) ([]*CertificateX, error) {
	p7, err := x509.ParsePKCS7(pbSignData)
	if err != nil {
		return nil, err
	}
	retArr := make([]*CertificateX, 0)
	for _, cert := range p7.Certificates {
		certx, err := CertificateXConstructorWithInterface(cert, nil)
		if err != nil {
			continue
		}
		retArr = append(retArr, certx)
	}
	return retArr, nil
}

func GetP1FromP7SignedData(pbSignData []byte) ([][]byte, error) {
	p7, err := x509.ParsePKCS7(pbSignData)
	if err != nil {
		return nil, err
	}
	retArr := make([][]byte, 0)
	for _, signer := range p7.Signers {
		p1 := signer.EncryptedDigest
		if err != nil {
			continue
		}
		retArr = append(retArr, p1)
	}
	return retArr, nil
}
