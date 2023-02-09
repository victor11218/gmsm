package main

import (
	"fmt"
	"github.com/roy19831015/gmsm/sm3"
	"github.com/roy19831015/gmsm/ucapp4go"
	"io/ioutil"
	"os"
)

func main() {
	if os.Args[1] == "-r" || os.Args[1] == "-R"{
		DoSm3Sum(os.Args[2])
		return
	}
	for i := 1; i < len(os.Args); i++ {
		strFilePath := os.Args[i]
		msg, err := ioutil.ReadFile(strFilePath)
		if err != nil {
			fmt.Printf("打开%s文件失败，详细信息："+err.Error()+"\n",strFilePath)
			continue
		}
		hash := sm3.Sm3Sum(msg)
		encode, err := ucapp4go.HexEncode(hash)
		if err != nil {
			fmt.Printf("对%s文件的摘要值做HexEncode失败，详细信息："+err.Error()+"\n",strFilePath)
			continue
		}
		fmt.Printf("%s的SM3摘要值为：%s\n", strFilePath, encode)
	}

}

func DoSm3Sum(dirName string) {
	dir, err := ioutil.ReadDir(dirName)
	if err != nil {
		return
	}
	for _, fi := range dir {
		if fi.IsDir(){
			DoSm3Sum(dirName+"/"+fi.Name())
			continue
		}
		strFilePath := dirName+"/"+fi.Name()
		msg, err := ioutil.ReadFile(strFilePath)
		if err != nil {
			fmt.Printf("打开%s文件失败，详细信息："+err.Error()+"\n",strFilePath)
			continue
		}
		hash := sm3.Sm3Sum(msg)
		encode, err := ucapp4go.HexEncode(hash)
		if err != nil {
			fmt.Printf("对%s文件的摘要值做HexEncode失败，详细信息："+err.Error()+"\n",strFilePath)
			continue
		}
		fmt.Printf("%s的SM3摘要值为：%s\n", strFilePath, encode)
	}
}
