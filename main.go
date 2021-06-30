package main

import (
	"bytes"
	"crypto/rsa"
	x5092 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/gofrs/uuid"
	"github.com/roy19831015/gmsm/log"
	"github.com/roy19831015/gmsm/sm2"
	"github.com/roy19831015/gmsm/ucapp4go"
	"github.com/roy19831015/gmsm/x509"
	"math/big"
	"math/rand"
	"time"
)

func main() {
	////test
	//cer,err := ucapp4go.CertificateXConstructorWithBase64String("MIIDqDCCA0ygAwIBAgIQJGhOG4szV7J+gwbGtrRIGzAMBggqgRzPVQGDdQUAMIGHMQswCQYDVQQGEwJDTjEOMAwGA1UECAwFSHViZWkxDjAMBgNVBAcMBVd1aGFuMTswOQYDVQQKDDJIdWJlaSBEaWdpdGFsIENlcnRpZmljYXRlIEF1dGhvcml0eSBDZW50ZXIgQ08gTHRkLjEMMAoGA1UECwwDRUNDMQ0wCwYDVQQDDARIQkNBMB4XDTIxMDUxODA1NTU1MFoXDTIyMDUxODA1NTU1MFowgYcxCzAJBgNVBAYTAkNOMQ8wDQYDVQQIDAbmuZbljJcxDzANBgNVBAcMBuatpuaxiTEkMCIGA1UECgwb5rGf5aSP5Yy656ys5LiA5Lq65rCR5Yy76ZmiMQ8wDQYDVQQLDAbpg6jpl6gxDDAKBgNVBAsMAzAwMTERMA8GA1UEAwwI5rWL6K+VNDYwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAS1o/pSmuec1Q+QMPnxd5Om2P8/SpNvSqeRuqmZL2e32cobvIxY02cgE+v99C8XoypHf02RAmN+v4OmUNElK8lko4IBlDCCAZAwHwYDVR0jBBgwFoAU9knnrFTTx/1tPRaTXOsoWePTQC0wEAYFVBALBwMEBwwFMTA0NjAwDAYDVR0TBAUwAwEBADARBgVUEAsHAQQIDAYqMTkyRyowgegGA1UdHwSB4DCB3TA0oDKgMKQuMCwxCzAJBgNVBAYTAkNOMQwwCgYDVQQLDANDUkwxDzANBgNVBAMMBmNybDgwNzAvoC2gK4YpaHR0cDovL3d3dy5oYmNhLm9yZy5jbi9jcmxfc20yL2NybDgwNy5jcmwwdKByoHCGbmxkYXA6Ly82MS4xODMuMTkxLjkwOjM4OS9DTj1jcmw4MDcsT1U9Q1JMLEM9Q04/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdGNsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MCMGBSqBHIdpBBoMGDFAMDAxMVNGMDQ0NDQ0NDQ0NDQ0NDQ0NDALBgNVHQ8EBAMCBsAwHQYDVR0OBBYEFDJmEOTz0Pj3NPJfvIyulrJyRpLPMAwGCCqBHM9VAYN1BQADSAAwRQIgTY8usoXHPTdW7LmWrE90V7ySGygUoKwZCqANosRa3C4CIQDfPo0oO358Adq3l099khA6uGSTHaIblGofXIWSaolmJA==","")
	//log.Info(cer.GetContent())
	////test
	//sm2
	sm2strPubBase64, sm2strPriBase64, sm2strP10Base64, err := ucapp4go.CreatePKCS10RequestString(ucapp4go.SM2, 256)
	if err != nil {
		log.Error("SM2产生P10请求错误，" + err.Error())
		return
	}
	rand.Seed(time.Now().UnixNano())
	guidCertSN, err := uuid.NewV4()
	certSN := big.NewInt(0).SetBytes(guidCertSN.Bytes())
	guidKeyId, err := uuid.NewV4()
	keyId := guidKeyId.Bytes()
	template := x509.Certificate{
		SerialNumber: certSN,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"湖北省数字证书认证管理中心有限公司"},
			OrganizationalUnit: []string{"技术部","服务器通讯证书"},
			Locality:           []string{"武汉市"},
			Province:           []string{"湖北省"},
			CommonName:         "HBCA协同签名系统",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       ucapp4go.OidExtensionSubjectKeyId,
				Critical: false,
				Value:    append([]byte{0x04, byte(len(keyId))}, keyId...),
			},
			{
				Id:       []int{2, 4, 16, 11, 7, 1},
				Critical: false,
				Value:    []byte{0x0c, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35},
			},
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          keyId,
		AuthorityKeyId:        keyId,
		OCSPServer:            []string{"http://61.183.191.90:20444"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		CRLDistributionPoints: []string{"http://61.183.191.90:389/ca1.crl"},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{[]int{1, 2, 3}},
	}
	sm2pbPriKeyData, err := ucapp4go.Base64Decode(sm2strPriBase64)
	if err != nil {
		log.Error("SM2产生私钥后Base64解码错误，" + err.Error())
		return
	}
	sm2PriKey, err := x509.ParsePKCS8PrivateKey(x509.SM2, sm2pbPriKeyData, nil)
	if err != nil {
		log.Error("SM2产生私钥后Base64解析错误，" + err.Error())
		return
	}
	sm2pbPubKeyData, err := ucapp4go.Base64Decode(sm2strPubBase64)
	if err != nil {
		log.Error("SM2产生公钥后Base64解码错误，" + err.Error())
		return
	}
	sm2PubKey, err := x509.ParseSm2PublicKey(sm2pbPubKeyData)
	if err != nil {
		log.Error("SM2产生公钥后Base64解析错误，" + err.Error())
		return
	}
	log.Debug("SM2产生P10接口生成的公钥值：" + string(sm2strPubBase64))
	log.Debug("SM2产生P10接口生成的私钥值：" + string(sm2strPriBase64))
	log.Debug("SM2产生P10接口生成的P10请求值：" + string(sm2strP10Base64))
	sm2pbcert, err := x509.CreateCertificate(&template, &template, sm2PubKey, sm2PriKey.(*sm2.PrivateKey))
	if err != nil {
		log.Error("SM2使用P10产生证书错误，" + err.Error())
		return
	}
	sm2cert, err := ucapp4go.Base64Encode(sm2pbcert)
	if err != nil {
		log.Error("SM2使用P10产生证书后Base64编码错误，" + err.Error())
		return
	}
	log.Debug("SM2使用P10产生证书：" + string(sm2cert))
	sm2p12, err := ucapp4go.CombineToPKCS12(sm2cert, sm2strPriBase64, "11111111", nil)
	if err != nil {
		log.Error("SM2使用P10产生证书后合成PFX错误，" + err.Error())
		return
	}
	sm2p12base64, err := ucapp4go.Base64Encode(sm2p12)
	if err != nil {
		log.Error("SM2使用P10产生证书后合成PFX的Base64编码错误，" + err.Error())
		return
	}
	log.Debug("SM2合并密钥和证书：" + sm2p12base64)
	//sm2p12base64 = "MIIFaAIBAzCCBTIGCSqGSIb3DQEHAaCCBSMEggUfMIIFGzCCA/8GCSqGSIb3DQEHBqCCA/AwggPsAgEAMIID5QYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIINZxa66AiK8CAggAgIIDuGrw1IUvHB0vx1OncMWpViwC+uZHwZd2M4uMimt8fudiKzyQj2CwAVD2FIx+bTZdK0hTJdXNpy9IGviV1NXkslO0yPuSg/W7KJceE8OW/ADXtODZRa2fpxesV2udkrW9tZsn6sCVFt0y2Qwp0Z8UsVRFsBHavVUNJLJqQovfs/1kDObgbkS7IusuVyVa6dgkq5wX+k6YKXoqoTJOZsyBDcrJkLlOqqM2IT9vglZHKrijdRExViB4+ydtYj0PoOmWvehnz1BqI0f+7unmJZghha8qbTUNNd8RX0EAIYqM+ZvRrdEBYlmqRlGNThZQV81vp4p1NEc1G1hAAZ5F3YVwK83DD9O+SflwlHpV3662rGEWtOVUdC8g6huIB2XVY0OlfBV1GZOku71z0VNCsx2G648ZpyQDyW6/Qk8L2Q/VLEECvFlats1SKENffhgPIT2YuMkcYpColG9DwK5yuHf4PxLzVjNwB9DBha8zXEADIDbfS04ca90rjVP/0VF9dSqYqdn6Cvp39qZNWBAuNEzhAfn7yI3FNpzvKQboGp5H8uVPXrNuN7/hPU32PhGKfaIdeSj87owIXQu36/GSjvNmluS1oa+CF2cpnMgV0d+3JJZnUj5zM5c+s8Cugk3oSCV8pLsb/TE+IMmhSuq1PwT1ehqzTjYVnFriTp9f6bpc1pQKQVS1bVFdxjlHAoNwQFOL+OwjCyf3VLTxzwlCNHONUcWvUWziuyiHvjFgnO2JRfcKAlP3Uf2ahutCjBAeYHRRni+ujbbDJ8WjZu+8/rFUXaL1JmFXnMcLJJhrFXEzdKWCmmrvt9lXVm8i1+0naRw+AX/niGP8b7k6NuFsl0i5RkCIrO6yaA4bW0aRmCIQqiSDwG+ekP5n6u21iz25gKSJ1WRP9rnhMnCBW1enNEuwHCUq4gwkC9A2rQUoMd5Xc9iPGrnx66pORAbEhKWfu9xUH+nOvxRxlhqvSdQCGOdI0CnsZmkB7+oTZp6OUk6tftJAYRfN396V3M3r4nXAo/bmY3H6aD1Y9IXocW3EwKb417JTavt0l8eeOv2gLYh1XC1hf323I7+ebVklxPSJkFILxhZ7a/LQZYDRAzgIZljuSoH9AquXabDtZiWq1wYMqCgFNQiC2Rdxh6Z+T5rAdaFx825FqxPV5sVnNwikNl744LtqX6OwGWFfXJ2UOiaMQnjvWyeRAw+iAQNa+ZG5VShD0Hu3LT8aOx7jYvhpwv+FlwSN5ylO7jpcCetLrrfM+vgnhRKu6sa5KaowggEUBgkqhkiG9w0BBwGgggEFBIIBATCB/jCB+wYLKoZIhvcNAQwKAQKggcQwgcEwHAYKKoZIhvcNAQwBAzAOBAij0aY8+HRpSQICCAAEgaDqGnBLsA5WPMKKRHe21juBxLDI3ni57PCuL8ffWpjjs31AYQZdlCEINpfarpyTefqX16fsOBg89K5PuVI9w1D5EWi/pK1I3qPBs9LaPJ2gILrITIJKewl7jw4jLu1KGO9hFJf7pKC4QyjmpbUh3lwPwkyDjR6gzHze5MWDZn4l6dg60jCHLdMSUQj5wWVEdBkmEQm7k6xQzOeY79xOVGv9MSUwIwYJKoZIhvcNAQkVMRYEFMuZB1+y6r8bXUd4DR1u+eiN+z1fMC0wITAJBgUrDgMCGgUABBSpxjw2YE9S8dmKQp7udX+56iYAvwQInpHqunXXeKo="
	sm2p12pin := "11111111"
	sm2certx, err := ucapp4go.PKCS12ParseCert(sm2p12base64, sm2p12pin)
	if err != nil {
		log.Error("SM2构造证书对象错误，" + err.Error())
		return
	}
	id, err := sm2certx.GetIssuerUniqueId()
	if err != nil {
		log.Error("SM2获取IssuerUID错误，" + err.Error())
		return
	}
	log.Debug("SM2的IssuerUID：" + id)
	id, err = sm2certx.GetSubjectUniqueId()
	if err != nil {
		log.Error("SM2获取SubjectUID错误，" + err.Error())
		return
	}
	log.Debug("SM2的SubjectUID：" + id)
	oidk := "2.4.16.11.7.1"
	oidv24161171, err := sm2certx.GetExtensionString(oidk)
	if err != nil {
		log.Error(`SM2获取oid"` + oidk + `"的值错误，` + err.Error())
		return
	}
	log.Info(`SM2获取oid"` + oidk + `"的值为` + oidv24161171)
	sm2certx.Pkcs1HashType = x509.SM3
	sm2pkcs1sign, err := sm2certx.PKCS1Sign([]byte("1234567890"))
	if err != nil {
		log.Error("SM2PKCS1签名错误，" + err.Error())
		return
	}
	sm2pkcs1signbase64, err := ucapp4go.Base64Encode(sm2pkcs1sign)
	log.Debug("SM2PKCS1签名值：" + string(sm2pkcs1signbase64))
	err = sm2certx.PKCS1Verify([]byte("1234567890"), sm2pkcs1sign)
	if err != nil {
		log.Error("SM2PKCS1验签失败，" + err.Error())
		return
	} else {
		log.Info("SM2PKCS1验签成功")
	}
	sm2certx.Pkcs7HashType = x509.SM3
	sm2pkcs7sign, err := sm2certx.PKCS7Sign([]byte("1234567890"), true)
	if err != nil {
		log.Error("SM2PKCS7签名错误，" + err.Error())
		return
	}
	sm2pkcs7signbase64, err := ucapp4go.Base64Encode(sm2pkcs7sign)
	log.Debug("SM2PKCS7签名值：" + string(sm2pkcs7signbase64))
	err = sm2certx.PKCS7Verify([]byte("1234567890"), sm2pkcs7sign)
	if err != nil {
		log.Error("SM2PKCS7验签失败，" + err.Error())
		return
	} else {
		log.Info("SM2PKCS7验签成功")
	}
	sm2encdata, err := sm2certx.PublicEncrypt([]byte("1234567890"))
	if err != nil {
		log.Error("SM2公钥加密错误，" + err.Error())
		return
	}
	sm2decdata, err := sm2certx.PrivateDecrypt(sm2encdata)
	if err != nil {
		log.Error("SM2私钥解密错误，" + err.Error())
		return
	}
	sm2encdatabase64, err := ucapp4go.Base64Encode(sm2encdata)
	log.Debug("SM2公钥加密密文值：" + string(sm2encdatabase64))
	if !bytes.Equal([]byte("1234567890"), sm2decdata) {
		log.Error("SM2私钥解密错误，解密出的原文" + string(sm2decdata) + "和加密时的原文" + string([]byte("1234567890")) + "不一致")
		return
	} else {
		log.Info("SM2私钥解密成功，解密出的原文" + string(sm2decdata) + "和加密时的原文" + string([]byte("1234567890")) + "一致")
	}
	sm2certx.EnvelopSymmType = ucapp4go.DESede
	sm2envdata, err := sm2certx.EnvSeal([]byte("1234567890"))
	if err != nil {
		log.Error("SM2数字信封加密错误，" + err.Error())
		return
	}
	sm2opendata, err := sm2certx.EnvOpen(sm2envdata)
	if err != nil {
		log.Error("SM2数字信封解密错误，" + err.Error())
		return
	}
	sm2envdatabase64, err := ucapp4go.Base64Encode(sm2envdata)
	log.Debug("SM2数字信封加密密文值：" + string(sm2envdatabase64))
	if !bytes.Equal([]byte("1234567890"), sm2opendata) {
		log.Error("SM2数字信封解密错误，解密出的原文" + string(sm2opendata) + "和加密时的原文" + string([]byte("1234567890")) + "不一致")
		return
	} else {
		log.Info("SM2数字信封解密成功，解密出的原文" + string(sm2opendata) + "和加密时的原文" + string([]byte("1234567890")) + "一致")
	}
	//rsa
	rsastrPubBase64, rsastrPriBase64, rsastrP10Base64, err := ucapp4go.CreatePKCS10RequestString(ucapp4go.RSA, 2048)
	if err != nil {
		log.Error("RSA产生P10请求错误，" + err.Error())
		return
	}
	rand.Seed(time.Now().UnixNano())
	guidCertSN, err = uuid.NewV4()
	certSN = big.NewInt(0).SetBytes(guidCertSN.Bytes())
	guidKeyId, err = uuid.NewV4()
	keyId = guidKeyId.Bytes()
	template = x509.Certificate{
		SerialNumber: certSN,
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"湖北省数字证书认证管理中心有限公司"},
			OrganizationalUnit: []string{"技术部"},
			Locality:           []string{"武汉市"},
			Province:           []string{"湖北省"},
			CommonName:         "Golang签发测试",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       ucapp4go.OidExtensionSubjectKeyId,
				Critical: false,
				Value:    append([]byte{0x04, byte(len(keyId))}, keyId...),
			},
			{
				Id:       []int{2, 4, 16, 11, 7, 1},
				Critical: false,
				Value:    []byte{0x0c, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35},
			},
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		SubjectKeyId:          keyId,
		AuthorityKeyId:        keyId,
		OCSPServer:            []string{"http://61.183.191.90:20444"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		CRLDistributionPoints: []string{"http://61.183.191.90:389/ca1.crl"},
		PolicyIdentifiers:     []asn1.ObjectIdentifier{[]int{1, 2, 3}},
	}
	rsapbPriKeyData, err := ucapp4go.Base64Decode(rsastrPriBase64)
	if err != nil {
		log.Error("RSA产生私钥后Base64解码错误，" + err.Error())
		return
	}
	rsaPriKey, err := x509.ParsePKCS8PrivateKey(x509.RSA, rsapbPriKeyData, nil)
	if err != nil {
		log.Error("RSA产生私钥后Base64解析错误，" + err.Error())
		return
	}
	rsapbPubKeyData, err := ucapp4go.Base64Decode(rsastrPubBase64)
	if err != nil {
		log.Error("RSA产生公钥后Base64解码错误，" + err.Error())
		return
	}
	rsaPubKey, err := x5092.ParsePKIXPublicKey(rsapbPubKeyData)
	if err != nil {
		log.Error("RSA产生公钥后Base64解析错误，" + err.Error())
		return
	}
	log.Debug("RSA产生P10接口生成的公钥值：" + string(rsastrPubBase64))
	log.Debug("RSA产生P10接口生成的私钥值：" + string(rsastrPriBase64))
	log.Debug("RSA产生P10接口生成的P10请求值：" + string(rsastrP10Base64))

	//TODO DELETE
	testpbcert, err := x509.CreateCertificate(&template, &template, rsaPubKey, sm2PriKey.(*sm2.PrivateKey))
	if err != nil {
		log.Error("TEST使用P10产生证书错误，" + err.Error())
		return
	}
	testcert, err := ucapp4go.Base64Encode(testpbcert)
	if err != nil {
		log.Error("TEST使用P10产生证书后Base64编码错误，" + err.Error())
		return
	}
	log.Debug("TEST使用P10产生证书：" + string(testcert))
	//TODO DELETE

	rsapbcert, err := x509.CreateCertificate(&template, &template, rsaPubKey, rsaPriKey.(*rsa.PrivateKey))
	if err != nil {
		log.Error("RSA使用P10产生证书错误，" + err.Error())
		return
	}
	rsacert, err := ucapp4go.Base64Encode(rsapbcert)
	if err != nil {
		log.Error("RSA使用P10产生证书后Base64编码错误，" + err.Error())
		return
	}
	log.Debug("RSA使用P10产生证书：" + string(sm2cert))
	rsap12, err := ucapp4go.CombineToPKCS12(rsacert, rsastrPriBase64, "11111111", nil)
	if err != nil {
		log.Error("RSA使用P10产生证书后合成PFX错误，" + err.Error())
		return
	}
	rsap12base64, err := ucapp4go.Base64Encode(rsap12)
	if err != nil {
		log.Error("RSA使用P10产生证书后合成PFX的Base64编码错误，" + err.Error())
		return
	}
	//rsap12base64 := "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"
	rsap12pin := "11111111"
	rsacertx, err := ucapp4go.PKCS12ParseCert(rsap12base64, rsap12pin)
	if err != nil {
		log.Error("RSA构造证书对象错误，" + err.Error())
		return
	}
	oidk = "2.4.16.11.7.1"
	oidv24161171, err = rsacertx.GetExtensionString(oidk)
	if err != nil {
		log.Error(`RSA获取oid"` + oidk + `"的值错误，` + err.Error())
		return
	}
	log.Info(`RSA获取oid"` + oidk + `"的值为` + oidv24161171)
	rsacertx.Pkcs1HashType = x509.SHA1
	rsapkcs1sign, err := rsacertx.PKCS1Sign([]byte("1234567890"))
	if err != nil {
		log.Error("RSAPKCS1签名错误，" + err.Error())
		return
	}
	rsapkcs1signbase64, err := ucapp4go.Base64Encode(rsapkcs1sign)
	log.Debug("RSAPKCS1签名值：" + string(rsapkcs1signbase64))
	err = rsacertx.PKCS1Verify([]byte("1234567890"), rsapkcs1sign)
	if err != nil {
		log.Error("RSAPKCS1验签失败，" + err.Error())
		return
	} else {
		log.Info("RSAPKCS1验签成功")
	}
	rsacertx.Pkcs7HashType = x509.SHA1
	rsapkcs7sign, err := rsacertx.PKCS7Sign([]byte("1234567890"), true)
	if err != nil {
		log.Error("RSAPKCS7签名错误，" + err.Error())
		return
	}
	rsapkcs7signbase64, err := ucapp4go.Base64Encode(rsapkcs7sign)
	log.Debug("RSAPKCS7签名值：" + string(rsapkcs7signbase64))
	err = rsacertx.PKCS7Verify([]byte("1234567890"), rsapkcs7sign)
	if err != nil {
		log.Error("RSAPKCS7验签失败，" + err.Error())
		return
	} else {
		log.Info("RSAPKCS7验签成功")
	}
	rsaencdata, err := rsacertx.PublicEncrypt([]byte("1234567890"))
	if err != nil {
		log.Error("RSA公钥加密错误，" + err.Error())
		return
	}
	rsadecdata, err := rsacertx.PrivateDecrypt(rsaencdata)
	if err != nil {
		log.Error("RSA私钥解密错误，" + err.Error())
		return
	}
	rsaencdatabase64, err := ucapp4go.Base64Encode(rsaencdata)
	log.Debug("RSA公钥加密密文值：" + string(rsaencdatabase64))
	if !bytes.Equal([]byte("1234567890"), rsadecdata) {
		log.Error("RSA私钥解密错误，解密出的原文" + string(rsadecdata) + "和加密时的原文" + string([]byte("1234567890")) + "不一致")
		return
	} else {
		log.Info("RSA私钥解密成功，解密出的原文" + string(rsadecdata) + "和加密时的原文" + string([]byte("1234567890")) + "一致")
	}
	rsacertx.EnvelopSymmType = ucapp4go.DESede
	rsaenvdata, err := rsacertx.EnvSeal([]byte("1234567890"))
	if err != nil {
		log.Error("RSA数字信封加密错误，" + err.Error())
		return
	}
	rsaopendata, err := rsacertx.EnvOpen(rsaenvdata)
	if err != nil {
		log.Error("RSA数字信封解密错误，" + err.Error())
		return
	}
	rsaenvdatabase64, err := ucapp4go.Base64Encode(rsaenvdata)
	log.Debug("RSA数字信封加密密文值：" + string(rsaenvdatabase64))
	if !bytes.Equal([]byte("1234567890"), rsaopendata) {
		log.Error("RSA数字信封解密错误，解密出的原文" + string(rsaopendata) + "和加密时的原文" + string([]byte("1234567890")) + "不一致")
		return
	} else {
		log.Info("RSA数字信封解密成功，解密出的原文" + string(rsaopendata) + "和加密时的原文" + string([]byte("1234567890")) + "一致")
	}

	p7 := `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`
	p7data, _ := ucapp4go.Base64Decode(p7)
	rsacertx.PKCS7Verify(nil, p7data)

	//TODO DELETE
	test2pbcert, err := x509.CreateCertificate(&template, &template, sm2PubKey, rsaPriKey.(*rsa.PrivateKey))
	if err != nil {
		log.Error("TEST2使用P10产生证书错误，" + err.Error())
		return
	}
	test2cert, err := ucapp4go.Base64Encode(test2pbcert)
	if err != nil {
		log.Error("TEST2使用P10产生证书后Base64编码错误，" + err.Error())
		return
	}
	log.Debug("TEST2使用P10产生证书：" + string(test2cert))
	//TODO DELETE
}
