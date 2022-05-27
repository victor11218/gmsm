package x509

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"github.com/gofrs/uuid"
	"github.com/victor11218/gmsm/sm2"
	"strings"
	"time"
)

type UserSealInfo struct {
	ImageInfo ImageInfo
	UserCert  []*Certificate
	SealName  string
	NotBefore time.Time
	NotAfter  time.Time
	SealType  int
}

type ImageInfo struct {
	Type      string
	ImageData []byte
	MMWidth   int
	MMHeight  int
}

type PKCS1Signer interface {
	GetPkcs1HashType() Hash
	PKCS1Sign([]byte) ([]byte, error)
	GetX509() (*Certificate, error)
}

type SealProviderInfo struct {
	Vid          string
	Remark       string
	ProviderCert PKCS1Signer
}

type SESeal struct {
	ESealInfo   SesSealInfo
	Cert        []byte
	SignAlgID   asn1.ObjectIdentifier
	SignedValue asn1.BitString
}

type SesSealInfo struct {
	Header   SesHeader
	EsId     string `asn1:"ia5"`
	Property SesESPropertyInfo
	Picture  SesESPictrueInfo
	ExtDatas []ExtData `asn1:"optional"`
}

type SesHeader struct {
	Id      string `asn1:"ia5"`
	Version int    `asn1:"default:4"`
	Vid     string `asn1:"ia5"`
}

type SesESPropertyInfo struct {
	Type         int
	Name         string `asn1:"utf8"`
	CertListType int
	CertList     SesCertList
	CreateDate   time.Time `asn1:"generalized"`
	ValidStart   time.Time `asn1:"generalized"`
	ValidEnd     time.Time `asn1:"generalized"`
}

type SesCertList struct {
	CertInfoList   []byte `asn1:"optional"`
	CertDigestList []byte `asn1:"optional"`
}

type CertDigestObj struct {
	Type  string `asn1:"printable"`
	Value asn1.RawValue
}

type SesESPictrueInfo struct {
	Type   string `asn1:"ia5"`
	Data   []byte
	Width  int
	Height int
}

type ExtData struct {
	ExtnID    asn1.ObjectIdentifier
	Critical  bool `asn1:"optional"`
	ExtnValue asn1.RawValue
}

type SesSignInfo struct {
	Cert               RawCertificates
	SignatureAlgorithm asn1.ObjectIdentifier
	SignData           asn1.BitString
}

func CreateSeal(usinfo *UserSealInfo, spInfo *SealProviderInfo) (*SESeal, error) {
	guid, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	strGuid := strings.ReplaceAll(guid.String(), "-", "")

	userCerts := make([]*Certificate, 0)
	for _, cert := range usinfo.UserCert {
		userCerts = append(userCerts, cert)
	}
	seseal := new(SESeal)
	rawCert, err := spInfo.ProviderCert.GetX509()
	if err != nil {
		return nil, err
	}
	seseal.Cert = rawCert.Raw
	seseal.ESealInfo = SesSealInfo{
		Header: SesHeader{
			Id:      "ES",
			Version: 4,
			Vid:     spInfo.Vid,
		},
		EsId: strGuid,
		Property: SesESPropertyInfo{
			Type:         usinfo.SealType,
			Name:         usinfo.SealName,
			CertListType: 1,
			CertList:     SesCertList{CertInfoList: MarshalCertificates(userCerts)},
			CreateDate:   time.Now(),
			ValidStart:   usinfo.NotBefore,
			ValidEnd:     usinfo.NotAfter,
		},
		Picture: SesESPictrueInfo{
			Type:   usinfo.ImageInfo.Type,
			Data:   usinfo.ImageInfo.ImageData,
			Width:  usinfo.ImageInfo.MMWidth,
			Height: usinfo.ImageInfo.MMHeight,
		},
	}
	tbsESeal, err := asn1.Marshal(seseal.ESealInfo)
	if err != nil {
		return nil, err
	}

	signData, err := spInfo.ProviderCert.PKCS1Sign(tbsESeal)

	seseal.SignedValue = asn1.BitString{
		Bytes:     signData,
		BitLength: 8 * len(signData),
	}

	switch rawCert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch spInfo.ProviderCert.GetPkcs1HashType() {
		case SHA1:
			seseal.SignAlgID = oidSignatureSHA1WithRSA
		case SHA256:
			seseal.SignAlgID = oidSignatureSHA256WithRSA
		default:
			return nil, errors.New("the sign algorithm is not support")
		}
	case *ecdsa.PublicKey, *sm2.PublicKey:
		switch spInfo.ProviderCert.GetPkcs1HashType() {
		case SHA1:
			seseal.SignAlgID = oidSignatureSM2WithSHA1
		case SHA256:
			seseal.SignAlgID = oidSignatureSM2WithSHA256
		case SM3:
			seseal.SignAlgID = oidSignatureSM2WithSM3
		default:
			return nil, errors.New("the sign algorithm is not support")
		}
	default:
		err = errors.New("the sign algorithm is not support")
	}

	return seseal, nil
}

type SesSignature struct {
	ToSign         TBS_Sign
	Cert           asn1.RawValue
	signatureAlgID asn1.ObjectIdentifier
	Signature      asn1.BitString
	TimeStamp      asn1.BitString `asn1:"optional,tag:0"`
}

type TBS_Sign struct {
	Version      int `asn1:"default:4"`
	ESeal        SESeal
	TimeInfo     time.Time
	DataHash     asn1.BitString
	PropertyInfo string
	ExtDatas     []ExtData `asn1:"optional"`
}
