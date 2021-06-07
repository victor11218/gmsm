package ucapp4go

import (
	"crypto"
	"encoding/asn1"
)

var (
	OidPBES1  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 3}  // pbeWithMD5AndDES-CBC(PBES1)
	OidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13} // id-PBES2(PBES2)
	OidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12} // id-PBKDF2

	OidKEYMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	OidKEYSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	OidKEYSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	OidKEYSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	OidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	OidSM2Encryption = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	OidRSAEncription = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	DefaultUID = []byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38}

	SM3Hash crypto.Hash = 0x00000401

	OidExtensionSubjectKeyId          = []int{2, 5, 29, 14}
	OidExtensionKeyUsage              = []int{2, 5, 29, 15}
	OidExtensionExtendedKeyUsage      = []int{2, 5, 29, 37}
	OidExtensionAuthorityKeyId        = []int{2, 5, 29, 35}
	OidExtensionBasicConstraints      = []int{2, 5, 29, 19}
	OidExtensionSubjectAltName        = []int{2, 5, 29, 17}
	OidExtensionCertificatePolicies   = []int{2, 5, 29, 32}
	OidExtensionNameConstraints       = []int{2, 5, 29, 30}
	OidExtensionCRLDistributionPoints = []int{2, 5, 29, 31}
	OidExtensionAuthorityInfoAccess   = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
)
