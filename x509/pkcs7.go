package x509

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	_ "crypto/sha1" // for crypto.SHA1
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/roy19831015/gmsm/sm2"
	"github.com/roy19831015/gmsm/sm4"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"sort"
	"time"
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	Certificates []*Certificate
	CRLs         []pkix.CertificateList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.156.10197.6.1.4.2.1), Signed Data (1.2.156.10197.6.1.4.2.2),
// and Enveloped Data are supported (1.2.156.10197.6.1.4.2.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

type unsignedData []byte

var (
	oidSMData                  = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 1}
	oidSMSignedData            = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 2}
	oidSMEnvelopedData         = asn1.ObjectIdentifier{1, 2, 156, 10197, 6, 1, 4, 2, 3}
	oidData                    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidSignedAndEnvelopedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 4}
	oidDigestedData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidEncryptedData           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidAttributeContentType    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttributeTimeStampToken = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
	oidSM3withSM2              = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 501}
	oidDSASM2                  = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 1}
	oidDSASM2Encryption        = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301, 3}
)

type signedData struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                contentInfo
	Certificates               RawCertificates        `asn1:"optional,tag:0"`
	CRLs                       []pkix.CertificateList `asn1:"optional,tag:1"`
	SignerInfos                []signerInfo           `asn1:"set"`
}

type RawCertificates struct {
	Raw asn1.RawContent
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// MessageDigestMismatchError is returned when the signer data digest does not
// match the computed digest for the contained content
type MessageDigestMismatchError struct {
	ExpectedDigest []byte
	ActualDigest   []byte
}

func (err *MessageDigestMismatchError) Error() string {
	return fmt.Sprintf("pkcs7: Message digest mismatch\n\tExpected: %X\n\tActual  : %X", err.ExpectedDigest, err.ActualDigest)
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

// ParsePKCS7 decodes a DER encoded PKCS7.
func ParsePKCS7(data []byte) (p7 *PKCS7, err error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	var info contentInfo
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}

	if err != nil {
		return
	}

	// fmt.Printf("--> Content Type: %s", info.ContentType)
	switch {
	case info.ContentType.Equal(oidSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(oidSMSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(oidEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	case info.ContentType.Equal(oidSMEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

func parseSignedData(data []byte) (*PKCS7, error) {
	var sd signedData
	asn1.Unmarshal(data, &sd)
	certs, err := sd.Certificates.Parse()
	if err != nil {
		return nil, err
	}
	// fmt.Printf("--> Signed Data Version %d\n", sd.Version)

	var compound asn1.RawValue
	var content unsignedData

	// The Content.Bytes maybe empty on PKI responses.
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &compound); err != nil {
			return nil, err
		}
	}
	// Compound octet string
	if compound.IsCompound {
		if _, err = asn1.Unmarshal(compound.Bytes, &content); err != nil {
			return nil, err
		}
	} else {
		// assuming this is tag 04
		content = compound.Bytes
	}
	return &PKCS7{
		Content:      content,
		Certificates: certs,
		CRLs:         sd.CRLs,
		Signers:      sd.SignerInfos,
		raw:          sd}, nil
}

func (raw RawCertificates) Parse() ([]*Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return ParseCertificates(val.Bytes)
}

func parseEnvelopedData(data []byte) (*PKCS7, error) {
	var ed envelopedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
}

// Verify checks the signatures of a PKCS7 object
// WARNING: Verify does not check signing time or verify certificate chains at
// this time.
func (p7 *PKCS7) Verify(certChain *CertPool, certCRL []*pkix.CertificateList, verifyTime *time.Time) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	for _, signer := range p7.Signers {
		if err := verifySignature(p7, signer, certChain, certCRL, verifyTime); err != nil {
			return err
		}
	}
	return nil
}

func downloadCRL(p string) (*pkix.CertificateList, error) {
	resp, err := http.Get(p)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("pkcs7: Close error: %v", err)
		}
	}(resp.Body)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return ParseCRL(body)
}

type VerifyOption struct {
	VerifyChain bool
	VerifyCRL   bool
}

// Verify checks the signatures of a PKCS7 object
// WARNING: Verify does not check signing time or verify certificate chains at
// this time.
func (p7 *PKCS7) VerifyWithPlainData(plainData []byte, certChain *CertPool, certCRL []*pkix.CertificateList, verifyTime *time.Time, opt VerifyOption) (err error) {
	if len(p7.Signers) == 0 {
		return errors.New("pkcs7: Message has no signers")
	}
	if p7.Content == nil || len(p7.Content) == 0 {
		p7.Content = plainData
	} else if plainData != nil && len(plainData) == 0 && bytes.Compare(p7.Content, plainData) != 0 {
		return errors.New("given plainData is different from plainData in attached pkcs7Data")
	}
	if opt.VerifyCRL {
		if certCRL == nil {
			for _, cert := range p7.Certificates {
				//downloadcrl
				points := cert.CRLDistributionPoints
				for _, p := range points {
					crl, err := downloadCRL(p)
					if err != nil {
						return err
					}
					certCRL = append(certCRL, crl)
				}
			}
		}
	} else {
		certCRL = nil
	}

	if !opt.VerifyChain {
		certChain = nil
	}
	for _, signer := range p7.Signers {
		if verifyTime == nil {
			attrArr := signer.AuthenticatedAttributes
			for _, attr := range attrArr {
				if attr.Type.Equal(oidAttributeSigningTime) {
					var signingTime time.Time
					_, err := asn1.Unmarshal(attr.Value.Bytes, &signingTime)
					if err != nil {
						continue
					}
					verifyTime = &signingTime
					break
				}
			}
		}
		if err := verifySignature(p7, signer, certChain, certCRL, verifyTime); err != nil {
			return err
		}
	}
	return nil
}

func verifyChain(cert *Certificate, certChain *CertPool) error {
	parents, _, _ := certChain.findVerifiedParents(cert)
	if len(parents) == 1 && certChain.certs[parents[0]].Equal(cert) {
		return nil
	}
	var err error
	for _, parent := range parents {
		err = verifyChain(certChain.certs[parent], certChain)
		if err == nil {
			return nil
		}
	}
	return err
}

func verifyCRL(cert *Certificate, crls []*pkix.CertificateList, verifyTime *time.Time) error {
	var vt time.Time
	if verifyTime == nil {
		vt = time.Now()
	} else {
		vt = *verifyTime
	}
	for _, crl := range crls {
		if crl.TBSCertList.Issuer.String() == cert.Issuer.String() {
			if crl.TBSCertList.RevokedCertificates != nil {
				for _, revokedCertSN := range crl.TBSCertList.RevokedCertificates {
					if revokedCertSN.SerialNumber.Cmp(cert.SerialNumber) == 0 {
						if verifyTime.After(revokedCertSN.RevocationTime) {
							return errors.New(`cert with serial number "` + cert.SerialNumber.Text(16) + `" is on CRL before the verifytime "` + vt.String() + `"`)
						}
					}
				}
			}
		}
	}
	return nil
}

func verifySignature(p7 *PKCS7, signer signerInfo, certChain *CertPool, certCRL []*pkix.CertificateList, verifyTime *time.Time) error {
	pbSignedData := p7.Content
	hash, err := getHashForOID(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	// fmt.Println("===== hash algo=====:", hash)
	if len(signer.AuthenticatedAttributes) > 0 {
		var digest []byte
		err := unmarshalAttribute(signer.AuthenticatedAttributes, oidAttributeMessageDigest, &digest)
		if err != nil {
			return err
		}
		h := hash.New()
		h.Write(p7.Content)
		computed := h.Sum(nil)
		if false && !hmac.Equal(digest, computed) {
			return &MessageDigestMismatchError{
				ExpectedDigest: digest,
				ActualDigest:   computed,
			}
		}
		// TODO(shengzhi): Optionally verify certificate chain
		// TODO(shengzhi): Optionally verify signingTime against certificate NotAfter/NotBefore
		pbSignedData, err = marshalAttributes(signer.AuthenticatedAttributes)
		if err != nil {
			return err
		}
	}
	if len(signer.UnauthenticatedAttributes) > 0 {
		var tst PKCS7
		err := p7.UnmarshalUnAttribute(oidAttributeTimeStampToken, &tst)
		if err != nil {
			var st time.Time
			err = p7.UnmarshalUnAttribute(oidAttributeSigningTime, &st)
			if err != nil {
				return err
			}
		}
	}
	cert := getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
	if cert == nil {
		return errors.New("pkcs7: No certificate for signer")
	}
	if certChain != nil {
		err = verifyChain(cert, certChain)
		if err != nil {
			return err
		}
		if certCRL != nil {
			err = verifyCRL(cert, certCRL, verifyTime)
		}
	}

	algo := getSignatureAlgorithmByHash(hash, signer.DigestEncryptionAlgorithm.Algorithm)
	if algo == UnknownSignatureAlgorithm {
		return ErrPKCS7UnsupportedAlgorithm
	}
	return cert.CheckSignature(algo, pbSignedData, signer.EncryptedDigest)
}

func getSignatureAlgorithmByHash(hash Hash, oid asn1.ObjectIdentifier) SignatureAlgorithm {
	switch hash {
	case SM3:
		switch {
		case oid.Equal(oidSM3withSM2):
			return SM2WithSM3
		case oid.Equal(oidDSASM2):
			return SM2WithSM3
		case oid.Equal(oidNamedCurveP256SM2):
			return SM2WithSM3
		}
	case SHA256:
		switch {
		case oid.Equal(oidDSASM2):
			return SM2WithSHA256
		case oid.Equal(oidSignatureSHA256WithRSA):
			return SHA256WithRSA
		case oid.Equal(oidPublicKeyRSA):
			return SHA256WithRSA
		}
	case SHA1:
		switch {
		case oid.Equal(oidSignatureSHA1WithRSA):
			return SHA1WithRSA
		case oid.Equal(oidPublicKeyRSA):
			return SHA1WithRSA
		}
	}
	return UnknownSignatureAlgorithm
}

func marshalAttributes(attrs []attribute) ([]byte, error) {
	encodedAttributes, err := asn1.Marshal(struct {
		A []attribute `asn1:"set"`
	}{A: attrs})
	if err != nil {
		return nil, err
	}

	// Remove the leading sequence octets
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(encodedAttributes, &raw)
	if err != nil {
		return nil, err
	}
	return raw.Bytes, nil
}

var (
	oidDigestAlgorithmSHA1    = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidEncryptionAlgorithmRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

func getCertFromCertsByIssuerAndSerial(certs []*Certificate, ias issuerAndSerial) *Certificate {
	for _, cert := range certs {
		if isCertMatchForIssuerAndSerial(cert, ias) {
			return cert
		}
	}
	return nil
}

func getHashForOID(oid asn1.ObjectIdentifier) (Hash, error) {
	switch {
	case oid.Equal(oidDigestAlgorithmSHA1):
		return SHA1, nil
	case oid.Equal(oidSHA256):
		return SHA256, nil
	case oid.Equal(oidSM3):
	case oid.Equal(oidHashSM3):
		return SM3, nil
	}
	return Hash(0), ErrPKCS7UnsupportedAlgorithm
}

func GetOIDForHash(hashType Hash) (asn1.ObjectIdentifier, error) {
	switch hashType {
	case SHA1:
		return oidDigestAlgorithmSHA1, nil
	case SHA256:
		return oidSHA256, nil
	case SM3:
		return oidHashSM3, nil
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

func getOIDForEncrypt(pubicKeyAlg PublicKeyAlgorithm) (asn1.ObjectIdentifier, error) {
	switch pubicKeyAlg {
	case RSA:
		return oidPublicKeyRSA, nil
	case DSA:
		return oidDSASM2Encryption, nil
	case ECDSA:
		return oidDSASM2Encryption, nil
	case SM2:
		return oidDSASM2Encryption, nil
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

func GetOIDForSign(pubicKeyAlg PublicKeyAlgorithm) (asn1.ObjectIdentifier, error) {
	switch pubicKeyAlg {
	case RSA:
		return oidPublicKeyRSA, nil
	case DSA:
		return oidDSASM2, nil
	case ECDSA:
		return oidDSASM2, nil
	case SM2:
		return oidDSASM2, nil
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

// GetOnlySigner returns an x509.Certificate for the first signer of the signed
// data payload. If there are more or less than one signer, nil is returned
func (p7 *PKCS7) GetOnlySigner() *Certificate {
	if len(p7.Signers) != 1 {
		return nil
	}
	signer := p7.Signers[0]
	return getCertFromCertsByIssuerAndSerial(p7.Certificates, signer.IssuerAndSerialNumber)
}

// ErrPKCS7UnsupportedAlgorithm tells you when our quick dev assumptions have failed
var ErrPKCS7UnsupportedAlgorithm = errors.New("pkcs7: cannot decrypt data: only RSA, DES, DES-EDE3, AES-256-CBC and AES-128-GCM supported")

// ErrNotEncryptedContent is returned when attempting to Decrypt data that is not encrypted data
var ErrNotEncryptedContent = errors.New("pkcs7: content data is a decryptable data type")

// Decrypt decrypts encrypted content info for recipient cert and private key
func (p7 *PKCS7) Decrypt(cert *Certificate, pk crypto.PrivateKey) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	switch pk.(type) {
	case *rsa.PrivateKey:
		priv := pk.(*rsa.PrivateKey)
		var contentKey []byte
		contentKey, err := rsa.DecryptPKCS1v15(rand.Reader, priv, recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	case *ecdsa.PrivateKey:
		priv := &sm2.PrivateKey{
			PublicKey: sm2.PublicKey{
				Curve: pk.(*ecdsa.PrivateKey).Curve,
				X:     pk.(*ecdsa.PrivateKey).X,
				Y:     pk.(*ecdsa.PrivateKey).Y,
			},
			D: pk.(*ecdsa.PrivateKey).D,
		}
		var contentKey []byte
		contentKey, err := sm2.DecryptAsn1(priv, recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	case *sm2.PrivateKey:
		priv := pk.(*sm2.PrivateKey)
		var contentKey []byte
		contentKey, err := sm2.DecryptAsn1(priv, recipient.EncryptedKey)
		if err != nil {
			return nil, err
		}
		return data.EncryptedContentInfo.decrypt(contentKey)
	default:
		fmt.Printf("Unsupported Private Key: %v\n", pk)
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

type PKCS1Decryptor interface {
	DecryptPKCS1([]byte) ([]byte, error)
}

// DecryptByDecryptor decrypts encrypted content info for recipient cert and outter private operate functions.
func (p7 *PKCS7) DecryptByDecryptor(cert *Certificate, decryptor PKCS1Decryptor) ([]byte, error) {
	data, ok := p7.raw.(envelopedData)
	if !ok {
		return nil, ErrNotEncryptedContent
	}
	recipient := selectRecipientForCertificate(data.RecipientInfos, cert)
	if recipient.EncryptedKey == nil {
		return nil, errors.New("pkcs7: no enveloped recipient for provided certificate")
	}
	contentKey, err := decryptor.DecryptPKCS1(recipient.EncryptedKey)
	if err != nil {
		return nil, err
	}
	return data.EncryptedContentInfo.decrypt(contentKey)
}

var oidEncryptionAlgorithmDESCBC = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
var oidEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
var oidEncryptionAlgorithmAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
var oidEncryptionAlgorithmAES128GCM = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
var oidEncryptionAlgorithmAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
var oidEncryptionAlgorithmSM4 = asn1.ObjectIdentifier{1, 2, 156, 197, 1, 104}
var oidEncryptionAlgorithmRC4 = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 4}
var oidEncryptionAlgorithmSM1 = asn1.ObjectIdentifier{1, 2, 156, 197, 1, 102}

func (eci EncryptedContentInfo) decrypt(key []byte) ([]byte, error) {
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	if !alg.Equal(oidEncryptionAlgorithmDESCBC) &&
		!alg.Equal(oidEncryptionAlgorithmDESEDE3CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES256CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128CBC) &&
		!alg.Equal(oidEncryptionAlgorithmAES128GCM) &&
		!alg.Equal(oidEncryptionAlgorithmSM4) {
		fmt.Printf("Unsupported Content Encryption Algorithm: %s\n", alg)
		return nil, ErrPKCS7UnsupportedAlgorithm
	}

	// EncryptedContent can either be constructed of multple OCTET STRINGs
	// or _be_ a tagged OCTET STRING
	var cyphertext []byte
	if eci.EncryptedContent.IsCompound {
		// Complex case to concat all of the children OCTET STRINGs
		var buf bytes.Buffer
		cypherbytes := eci.EncryptedContent.Bytes
		for {
			var part []byte
			cypherbytes, _ = asn1.Unmarshal(cypherbytes, &part)
			buf.Write(part)
			if cypherbytes == nil {
				break
			}
		}
		cyphertext = buf.Bytes()
	} else {
		// Simple case, the bytes _are_ the cyphertext
		cyphertext = eci.EncryptedContent.Bytes
	}

	var block cipher.Block
	var err error

	switch {
	case alg.Equal(oidEncryptionAlgorithmSM4):
		block, err = sm4.NewCipher(key)
	case alg.Equal(oidEncryptionAlgorithmDESCBC):
		block, err = des.NewCipher(key)
	case alg.Equal(oidEncryptionAlgorithmDESEDE3CBC):
		block, err = des.NewTripleDESCipher(key)
	case alg.Equal(oidEncryptionAlgorithmAES256CBC):
		fallthrough
	case alg.Equal(oidEncryptionAlgorithmAES128GCM), alg.Equal(oidEncryptionAlgorithmAES128CBC):
		block, err = aes.NewCipher(key)
	}

	if err != nil {
		return nil, err
	}

	if alg.Equal(oidEncryptionAlgorithmAES128GCM) {
		params := aesGCMParameters{}
		paramBytes := eci.ContentEncryptionAlgorithm.Parameters.Bytes

		_, err := asn1.Unmarshal(paramBytes, &params)
		if err != nil {
			return nil, err
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		if len(params.Nonce) != gcm.NonceSize() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}
		if params.ICVLen != gcm.Overhead() {
			return nil, errors.New("pkcs7: encryption algorithm parameters are incorrect")
		}

		plaintext, err := gcm.Open(nil, params.Nonce, cyphertext, nil)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	}

	iv := eci.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, errors.New("pkcs7: encryption algorithm parameters are malformed")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(cyphertext))
	mode.CryptBlocks(plaintext, cyphertext)
	if plaintext, err = unpad(plaintext, mode.BlockSize()); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func selectRecipientForCertificate(recipients []recipientInfo, cert *Certificate) recipientInfo {
	for _, recp := range recipients {
		if isCertMatchForIssuerAndSerial(cert, recp.IssuerAndSerialNumber) {
			return recp
		}
	}
	return recipientInfo{}
}

func isCertMatchForIssuerAndSerial(cert *Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Compare(cert.RawIssuer, ias.IssuerName.FullBytes) == 0
}

func pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := blocklen - (len(data) % blocklen)
	if padlen == 0 {
		padlen = blocklen
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func unmarshalAttribute(attrs []attribute, attributeType asn1.ObjectIdentifier, out interface{}) error {
	for _, attr := range attrs {
		if attr.Type.Equal(attributeType) {
			_, err := asn1.Unmarshal(attr.Value.Bytes, out)
			return err
		}
	}
	return errors.New("pkcs7: attribute type not in attributes")
}

// UnmarshalSignedAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalSignedAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].AuthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

// UnmarshalAttribute decodes a single attribute from the signer info
func (p7 *PKCS7) UnmarshalUnAttribute(attributeType asn1.ObjectIdentifier, out interface{}) error {
	sd, ok := p7.raw.(signedData)
	if !ok {
		return errors.New("pkcs7: payload is not signedData content")
	}
	if len(sd.SignerInfos) < 1 {
		return errors.New("pkcs7: payload has no signers")
	}
	attributes := sd.SignerInfos[0].UnauthenticatedAttributes
	return unmarshalAttribute(attributes, attributeType, out)
}

// SignedData is an opaque data structure for creating signed data payloads
type SignedData struct {
	sd            signedData
	certs         []*Certificate
	messageDigest []byte
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

// SignerInfoConfig are optional values to include when adding a signer
type SignerInfoConfig struct {
	ExtraSignedAttributes []Attribute
}

// NewSignedData initializes a SignedData with content
func NewSignedData(data []byte) (*SignedData, error) {
	content, err := asn1.Marshal(data)
	if err != nil {
		return nil, err
	}
	ci := contentInfo{
		ContentType: oidData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	digAlg := pkix.AlgorithmIdentifier{
		Algorithm: oidDigestAlgorithmSHA1,
	}
	h := crypto.SHA1.New()
	h.Write(data)
	md := h.Sum(nil)
	sd := signedData{
		ContentInfo:                ci,
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digAlg},
	}
	return &SignedData{sd: sd, messageDigest: md}, nil
}

func NewP7B(certs []*Certificate) (*SignedData, error) {
	ci := contentInfo{ContentType: oidData}
	sd := signedData{
		ContentInfo:                ci,
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{},
	}
	sd.SignerInfos = []signerInfo{}

	return &SignedData{sd: sd, certs: certs, messageDigest: nil}, nil
}

// NewPKCS7SignedData initializes a PKCS7SignedData with content
func NewPKCS7SignedData(data []byte, pkcs1SignedData []byte, hashType Hash, signCert *Certificate) (*SignedData, error) {
	var ci contentInfo
	if data != nil {
		content, err := asn1.Marshal(data)
		if err != nil {
			return nil, err
		}
		ci = contentInfo{
			ContentType: oidData,
			Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
		}
	} else {
		ci = contentInfo{ContentType: oidData}
	}
	algOid, err := GetOIDForHash(hashType)
	if err != nil {
		return nil, err
	}
	digAlg := pkix.AlgorithmIdentifier{
		Algorithm: algOid,
	}
	sd := signedData{
		ContentInfo:                ci,
		Version:                    1,
		DigestAlgorithmIdentifiers: []pkix.AlgorithmIdentifier{digAlg},
	}
	ias, err := cert2issuerAndSerial(signCert)
	if err != nil {
		return nil, err
	}
	sigOid, err := GetOIDForSign(signCert.PublicKeyAlgorithm)

	//
	attrs := attributes{}
	attrs.Add(oidAttributeSigningTime, time.Now())
	attrArr, err := attrs.ForMarshaling()
	if err != nil {
		return nil, err
	}
	//

	signer := signerInfo{
		UnauthenticatedAttributes: attrArr,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: algOid},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOid},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           pkcs1SignedData,
		Version:                   1,
	}
	sd.SignerInfos = []signerInfo{signer}

	return &SignedData{sd: sd, certs: []*Certificate{signCert}, messageDigest: nil}, nil
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshaling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}

// AddSigner signs attributes about the content and adds certificate to payload
func (sd *SignedData) AddSigner(cert *Certificate, pkey crypto.PrivateKey, config SignerInfoConfig) error {
	attrs := &attributes{}
	attrs.Add(oidAttributeContentType, sd.sd.ContentInfo.ContentType)
	attrs.Add(oidAttributeMessageDigest, sd.messageDigest)
	attrs.Add(oidAttributeSigningTime, time.Now())
	for _, attr := range config.ExtraSignedAttributes {
		attrs.Add(attr.Type, attr.Value)
	}
	finalAttrs, err := attrs.ForMarshaling()
	if err != nil {
		return err
	}
	signature, err := signAttributes(finalAttrs, pkey, crypto.SHA1)
	if err != nil {
		return err
	}

	ias, err := cert2issuerAndSerial(cert)
	if err != nil {
		return err
	}

	signer := signerInfo{
		AuthenticatedAttributes:   finalAttrs,
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: oidDigestAlgorithmSHA1},
		DigestEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureSHA1WithRSA},
		IssuerAndSerialNumber:     ias,
		EncryptedDigest:           signature,
		Version:                   1,
	}
	// create signature of signed attributes
	sd.certs = append(sd.certs, cert)
	sd.sd.SignerInfos = append(sd.sd.SignerInfos, signer)
	return nil
}

// AddCertificate adds the certificate to the payload. Useful for parent certificates
func (sd *SignedData) AddCertificate(cert *Certificate) {
	sd.certs = append(sd.certs, cert)
}

// Detach removes content from the signed data struct to make it a detached signature.
// This must be called right before Finish()
func (sd *SignedData) Detach() {
	sd.sd.ContentInfo = contentInfo{ContentType: oidData}
}

// Finish marshals the content and its signers
func (sd *SignedData) Finish() ([]byte, error) {
	sd.sd.Certificates = marshalCertificates(sd.certs)
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

// Finish marshals the content and its signers
func (sd *SignedData) DirectFinish() ([]byte, error) {
	sd.sd.Certificates = marshalCertificates(sd.certs)
	inner, err := asn1.Marshal(sd.sd)
	if err != nil {
		return nil, err
	}
	outer := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: inner, IsCompound: true},
	}
	return asn1.Marshal(outer)
}

func cert2issuerAndSerial(cert *Certificate) (issuerAndSerial, error) {
	var ias issuerAndSerial
	// The issuer RDNSequence has to match exactly the sequence in the certificate
	// We cannot use cert.Issuer.ToRDNSequence() here since it mangles the sequence
	ias.IssuerName = asn1.RawValue{FullBytes: cert.RawIssuer}
	ias.SerialNumber = cert.SerialNumber

	return ias, nil
}

// signs the DER encoded form of the attributes with the private key
func signAttributes(attrs []attribute, pkey crypto.PrivateKey, hash crypto.Hash) ([]byte, error) {
	attrBytes, err := marshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	h := hash.New()
	h.Write(attrBytes)
	hashed := h.Sum(nil)
	switch priv := pkey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA1, hashed)
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

// concats and wraps the certificates in the RawValue structure
func marshalCertificates(certs []*Certificate) RawCertificates {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	rawCerts, _ := marshalCertificateBytes(buf.Bytes())
	return rawCerts
}

// Even though, the tag & length are stripped out during marshalling the
// RawContent, we have to encode it into the RawContent. If its missing,
// then `asn1.Marshal()` will strip out the certificate wrapper instead.
func marshalCertificateBytes(certs []byte) (RawCertificates, error) {
	var val = asn1.RawValue{Bytes: certs, Class: 2, Tag: 0, IsCompound: true}
	b, err := asn1.Marshal(val)
	if err != nil {
		return RawCertificates{}, err
	}
	return RawCertificates{Raw: b}, nil
}

func MarshalCertificates(certs []*Certificate) []byte {
	var buf bytes.Buffer
	for _, cert := range certs {
		buf.Write(cert.Raw)
	}
	return buf.Bytes()
}

// DegenerateCertificate creates a signed data structure containing only the
// provided certificate or certificate chain.
func DegenerateCertificate(cert []byte) ([]byte, error) {
	rawCert, err := marshalCertificateBytes(cert)
	if err != nil {
		return nil, err
	}
	emptyContent := contentInfo{ContentType: oidData}
	sd := signedData{
		Version:      1,
		ContentInfo:  emptyContent,
		Certificates: rawCert,
		CRLs:         []pkix.CertificateList{},
	}
	content, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	signedContent := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, Bytes: content, IsCompound: true},
	}
	return asn1.Marshal(signedContent)
}

//AES256 SymmType = iota - 1
//SM4
//DES
//DESede
//SM1
const (
	EncryptionAlgorithmDESCBC = iota
	EncryptionAlgorithmAES128GCM
	EncryptionAlgorithmAES256
	EncryptionAlgorithmSM4
	EncryptionAlgorithmDESede
	EncryptionAlgorithmSM1
	EncryptionAlgorithmRC4
	EncryptionAlgorithmAES256EmptyIV
)

// ContentEncryptionAlgorithm determines the algorithm used to encrypt the
// plaintext message. Change the value of this variable to change which
// algorithm is used in the Encrypt() function.
var ContentEncryptionAlgorithm = EncryptionAlgorithmDESCBC

// ErrUnsupportedEncryptionAlgorithm is returned when attempting to encrypt
// content with an unsupported algorithm.
var ErrUnsupportedEncryptionAlgorithm = errors.New("pkcs7: cannot encrypt content: only DES-CBC and AES-128-GCM supported")

const nonceSize = 12

type aesGCMParameters struct {
	Nonce  []byte `asn1:"tag:4"`
	ICVLen int
}

func encryptRC4(content []byte) ([]byte, *EncryptedContentInfo, error) {
	// Create SM4 key & CBC IV
	key := make([]byte, 16)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	// Encrypt padded content
	block, err := rc4.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	plaintext := content
	cyphertext := make([]byte, len(plaintext))
	block.XORKeyStream(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmRC4,
			Parameters: asn1.RawValue{Tag: 4, Bytes: nil},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptAES128GCM(content []byte) ([]byte, *EncryptedContentInfo, error) {
	// Create AES key and nonce
	key := make([]byte, 16)
	nonce := make([]byte, nonceSize)

	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, content, nil)

	// Prepare ASN.1 Encrypted Content Info
	paramSeq := aesGCMParameters{
		Nonce:  nonce,
		ICVLen: gcm.Overhead(),
	}

	paramBytes, err := asn1.Marshal(paramSeq)
	if err != nil {
		return nil, nil, err
	}

	eci := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidEncryptionAlgorithmAES128GCM,
			Parameters: asn1.RawValue{
				Tag:   asn1.TagSequence,
				Bytes: paramBytes,
			},
		},
		EncryptedContent: marshalEncryptedContent(ciphertext),
	}

	return key, &eci, nil
}

func encryptDESCBC(content []byte) ([]byte, *EncryptedContentInfo, error) {
	// Create DES key & CBC IV
	key := make([]byte, 8)
	iv := make([]byte, des.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmDESCBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptSM4(content []byte) ([]byte, *EncryptedContentInfo, error) {
	// Create SM4 key & CBC IV
	key := make([]byte, 16)
	iv := make([]byte, sm4.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmSM4,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptAES256(content []byte) ([]byte, *EncryptedContentInfo, error) {
	// Create SM4 key & CBC IV
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmAES256CBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptAES256WithZeroIV(content []byte) ([]byte, *EncryptedContentInfo, error) {
	// Create SM4 key & CBC IV
	key := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmAES256CBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func encryptDESede(content []byte) ([]byte, *EncryptedContentInfo, error) {
	// Create SM4 key & CBC IV
	key := make([]byte, 24)
	iv := make([]byte, des.BlockSize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, nil, err
	}
	_, err = rand.Read(iv)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt padded content
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	plaintext, err := pad(content, mode.BlockSize())
	cyphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(cyphertext, plaintext)

	// Prepare ASN.1 Encrypted Content Info
	eci := EncryptedContentInfo{
		ContentType: oidData,
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidEncryptionAlgorithmDESEDE3CBC,
			Parameters: asn1.RawValue{Tag: 4, Bytes: iv},
		},
		EncryptedContent: marshalEncryptedContent(cyphertext),
	}

	return key, &eci, nil
}

func ExchangeKeyEncrypt(content []byte, recipient *Certificate, contentEncryptionAlgorithm int) (eci *EncryptedContentInfo, rcptInfo *recipientInfo, err error) {
	var key []byte

	// Apply chosen symmetric encryption method
	switch contentEncryptionAlgorithm {
	case EncryptionAlgorithmAES256EmptyIV:
		key, eci, err = encryptAES256WithZeroIV(content)
	case EncryptionAlgorithmAES256:
		key, eci, err = encryptAES256(content)
	case EncryptionAlgorithmSM4:
		key, eci, err = encryptSM4(content)
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content)
	case EncryptionAlgorithmDESede:
		key, eci, err = encryptDESede(content)
	case EncryptionAlgorithmSM1:
		return nil, nil, errors.New("sm1 symm algorithm is not supported")
	case EncryptionAlgorithmAES128GCM:
		key, eci, err = encryptAES128GCM(content)
	case EncryptionAlgorithmRC4:
		key, eci, err = encryptRC4(content)
	default:
		return nil, nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, nil, err
	}
	// Prepare each recipient's encrypted cipher key
	var haveSm2 bool = false

	isSm2 := recipient.PublicKeyAlgorithm == RSA
	haveSm2 = haveSm2 || isSm2
	encrypted, err := encryptKeyEx(key, recipient)
	if err != nil {
		return nil, nil, err
	}
	ias, err := cert2issuerAndSerial(recipient)
	if err != nil {
		return nil, nil, err
	}
	encoid, err := getOIDForEncrypt(recipient.PublicKeyAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	rcptInfo = &recipientInfo{
		Version:               0,
		IssuerAndSerialNumber: ias,
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: encoid,
		},
		EncryptedKey: encrypted,
	}

	return eci, rcptInfo, nil
}

// Encrypt creates and returns an envelope data PKCS7 structure with encrypted
// recipient keys for each recipient public key.
//
// The algorithm used to perform encryption is determined by the current value
// of the global ContentEncryptionAlgorithm package variable. By default, the
// value is EncryptionAlgorithmDESCBC. To use a different algorithm, change the
// value before calling Encrypt(). For example:
//
//     ContentEncryptionAlgorithm = EncryptionAlgorithmAES128GCM
//
// TODO(fullsailor): Add support for encrypting content with other algorithms
func PKCS7Encrypt(content []byte, recipients []*Certificate, contentEncryptionAlgorithm int) ([]byte, error) {
	var eci *EncryptedContentInfo
	var key []byte
	var err error

	// Apply chosen symmetric encryption method
	switch contentEncryptionAlgorithm {
	case EncryptionAlgorithmAES256:
		key, eci, err = encryptAES256(content)
	case EncryptionAlgorithmSM4:
		key, eci, err = encryptSM4(content)
	case EncryptionAlgorithmDESCBC:
		key, eci, err = encryptDESCBC(content)
	case EncryptionAlgorithmDESede:
		key, eci, err = encryptDESede(content)
	case EncryptionAlgorithmSM1:
		return nil, errors.New("sm1 symm algorithm is not supported")
	case EncryptionAlgorithmAES128GCM:
		key, eci, err = encryptAES128GCM(content)

	default:
		return nil, ErrUnsupportedEncryptionAlgorithm
	}

	if err != nil {
		return nil, err
	}

	// Prepare each recipient's encrypted cipher key
	recipientInfos := make([]recipientInfo, len(recipients))
	var haveSm2 bool = false
	for i, recipient := range recipients {
		isSm2 := recipient.PublicKeyAlgorithm == RSA
		haveSm2 = haveSm2 || isSm2
		encrypted, err := encryptKeyEx(key, recipient)
		if err != nil {
			return nil, err
		}
		ias, err := cert2issuerAndSerial(recipient)
		if err != nil {
			return nil, err
		}
		encoid, err := getOIDForEncrypt(recipient.PublicKeyAlgorithm)
		if err != nil {
			return nil, err
		}
		info := recipientInfo{
			Version:               0,
			IssuerAndSerialNumber: ias,
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: encoid,
			},
			EncryptedKey: encrypted,
		}
		recipientInfos[i] = info
	}

	// Prepare envelope content
	envelope := envelopedData{
		EncryptedContentInfo: *eci,
		Version:              0,
		RecipientInfos:       recipientInfos,
	}
	innerContent, err := asn1.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	var oidEnvData asn1.ObjectIdentifier
	if haveSm2 {
		oidEnvData = oidEnvelopedData
	} else {
		oidEnvData = oidSMEnvelopedData
	}
	// Prepare outer payload structure
	wrapper := contentInfo{

		ContentType: oidEnvData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: innerContent},
	}

	return asn1.Marshal(wrapper)
}

func marshalEncryptedContent(content []byte) asn1.RawValue {
	asn1Content, _ := asn1.Marshal(content)
	return asn1.RawValue{Tag: 0, Class: 2, Bytes: asn1Content, IsCompound: true}
}

func encryptKey(key []byte, recipient *Certificate) ([]byte, error) {
	if pub := recipient.PublicKey.(*rsa.PublicKey); pub != nil {
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	}
	return nil, ErrPKCS7UnsupportedAlgorithm
}

func encryptKeyEx(key []byte, recipient *Certificate) ([]byte, error) {
	switch recipient.PublicKey.(type) {
	case *rsa.PublicKey:
		pub := recipient.PublicKey.(*rsa.PublicKey)
		return rsa.EncryptPKCS1v15(rand.Reader, pub, key)
	case *sm2.PublicKey:
		pub := recipient.PublicKey.(*sm2.PublicKey)
		return sm2.EncryptAsn1(pub, key, rand.Reader)
	case *ecdsa.PublicKey:
		pub := &sm2.PublicKey{
			Curve: recipient.PublicKey.(*ecdsa.PublicKey).Curve,
			X:     recipient.PublicKey.(*ecdsa.PublicKey).X,
			Y:     recipient.PublicKey.(*ecdsa.PublicKey).Y,
		}
		return sm2.EncryptAsn1(pub, key, rand.Reader)
	default:
		return nil, errors.New("invalid public key type")
	}
}
