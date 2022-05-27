package main

import (
	"fmt"
	"github.com/victor11218/gmsm/sm3"
	"github.com/victor11218/gmsm/ucapp4go"
	"github.com/victor11218/gmsm/x509"
	"io/ioutil"
	"os"
)

var strP12Base64 = "MIIFKAIBAzCCBPIGCSqGSIb3DQEHAaCCBOMEggTfMIIE2zCCA78GCSqGSIb3DQEHBqCCA7AwggOsAgEAMIIDpQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQI9Zv1w1x9Xz4CAggAgIIDeMszbquUDAlU58gkrpAyLFPSvfxqUEhjAd8BRWtVy7fruA66al304TFFe/byhL4inoVKlklj8NMPD+Y00esVtk+L4U0oprdJF/QJPatnXg/O/NTNBEwBhCf/8VFMzlDiUQBF0rWopa+Lpy2PUhldV/pQltiYtnHm6nnwMbJEP8iwscO6b1k4KNYvr0pgbrC2fXXotzmKQagkx8nZKRNqRXCiJONLsH59kA+oO+M5VFcaPDMWMrb4/JZw1Gz0/PHI+aL0fza+sRcx6tn6lAuYz3YQXGVqc4nAVUjLGhxR0Nl4dxa9hB8yn5f+Cr1Z+Mz9Y6GymgxxuW9pJm7xZTTpVVo+q8sqR8kTkqz9ERjpkMcF+JaOnL6X365jYz7dFypxrag4ClGJ9fhxbkKLnr32KVC+nBADprWrTXEgRd9aUjEEfKnYBh5uVm8j5deFKhHBfSqhSU3XhAYscVgrZcCMCObPmuKWIUL77YQsnDbYegMWkyMa87xN/7C2EwwJyCpBXoR5twGtuvl30N7GsYNFBKJSfusfwnrHde0kQhNU5jvWiywEuGlYRDCsWMNNiTsJH60jys04yP15jRVmgz8YFJrhq6JIfdgUWFFFfhDprcI89+eoP5eDw1F9ZOkrztQN7pGhubMGTt5IYEKJxPiIGT7faHU8JkWDel53QtSHequEmjshF2c5jHkg+wq8XpHTel+qxLRid/rOtRO5UW5kn4huP40VWtX4b5En7sV6JxqcfmavpUOr+vu36J3+BAdB5tJtwWWGhZjtQNIsPYE8pwexM9htwBgSnkJNZMD92iYzERspgnNe5gGHQrhjoWcX75HIk9Y5bKGEKA7q1349Y1WMCZscDSj/Fx7NGGekZFP0mIUwxiPEg4ETyLnbh0ibQBurWLbl6BZVCVIzq+UzO3EQdbQmABLmWb6MyON0N7qRUuORcdE4NfLn0ENYqzjwRNOVSef/gJem44l5dHK63eQTyYlXVN02obKsGXke7ZQfRqvprxFg0kKityCjVPN//N3+DxIXuog5wbAP33nYsxVC6HGfqo5jOhQIrHs2ATyVOYwwes20S0UflEqeOrN+rdCjuXyFQ6JGVBLJlp0oXqN/ALyOseBFD0kWf5+qP9hnxwGyIGF6J82oahgXGp/7GXpSWSIdcwUYXW4SKOT+c/uhYGVJ9N+/SjCCARQGCSqGSIb3DQEHAaCCAQUEggEBMIH+MIH7BgsqhkiG9w0BDAoBAqCBxDCBwTAcBgoqhkiG9w0BDAEDMA4ECBBr7EHwU4XYAgIIAASBoF9ToWzTuz51ssNJV5PW9n2oEAzI3yWWpqeX7V0oVvCs6uqG2a74fSxByxuurIWtmvk6+RMaOX26sh7PYdkxf9sqBST+sN/ZmP26UWJRKH0Q3FxideobOVOGXhP7xmxpCB4aLBzPeT8K32VfysoGZv4YM/EPZ9IusMMX51fnRaooE/kzfvrBTksjZj96LRG4M/HXBXrGAPB1hmfha8Acc4kxJTAjBgkqhkiG9w0BCRUxFgQUemAs0zRBXN1Fj/BKTF5gylVjcgMwLTAhMAkGBSsOAwIaBQAEFOXGTVdzGclEaY/xoCDWaWi1IlsxBAjZFNgd6IVkCg=="
var certx *ucapp4go.CertificateX

func main() {
	certx, err := ucapp4go.PKCS12ParseCert(strP12Base64, "11111111")
	if err != nil {
		return
	}
	if os.Args[1] == "-r" || os.Args[1] == "-R" {
		doSm3Sum(os.Args[2])
		return
	}
	for i := 1; i < len(os.Args); i++ {
		strFilePath := os.Args[i]
		msg, err := ioutil.ReadFile(strFilePath)
		if err != nil {
			fmt.Printf("打开%s文件失败，详细信息：" + err.Error() + "\n")
			continue
		}
		hash := sm3.Sm3Sum(msg)
		certx.Pkcs1HashType = x509.SM3
		signed, err := certx.PKCS1Sign(hash)
		if err != nil {
			fmt.Printf("对%s文件的摘要值做签名失败，详细信息：" + err.Error() + "\n")
			continue
		}
		encode, err := ucapp4go.Base64Encode(signed)
		if err != nil {
			fmt.Printf("对%s文件的签名值做Base64编码失败，详细信息：" + err.Error() + "\n")
			continue
		}
		fmt.Printf("%s的签名值为：%s\n", strFilePath, encode)
	}

}

func doSm3Sum(dirName string) {
	dir, err := ioutil.ReadDir(dirName)
	if err != nil {
		return
	}
	for _, fi := range dir {
		if fi.IsDir() {
			doSm3Sum(fi.Name())
			continue
		}
		strFilePath := fi.Name()
		msg, err := ioutil.ReadFile(strFilePath)
		if err != nil {
			fmt.Printf("打开%s文件失败，详细信息：" + err.Error() + "\n")
			continue
		}
		hash := sm3.Sm3Sum(msg)
		certx.Pkcs1HashType = x509.SM3
		signed, err := certx.PKCS1Sign(hash)
		if err != nil {
			fmt.Printf("对%s文件的摘要值做签名失败，详细信息：" + err.Error() + "\n")
			continue
		}
		encode, err := ucapp4go.Base64Encode(signed)
		if err != nil {
			fmt.Printf("对%s文件的签名值做Base64编码失败，详细信息：" + err.Error() + "\n")
			continue
		}
		fmt.Printf("%s的签名值为：%s\n", strFilePath, encode)
	}
}
