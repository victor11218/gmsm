package main

import (
	"crypto/rand"
	"fmt"
	"github.com/roy19831015/gmsm/sm2"
	"github.com/roy19831015/gmsm/ucapp4go"
)

func main()  {
	key, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	fmt.Printf("D:%s", key.D.Text(16)+"\n")
	fmt.Printf("X:%s", key.X.Text(16)+"\n")
	fmt.Printf("Y:%s", key.Y.Text(16)+"\n")
	msg,_:=ucapp4go.HexDecode("0665F610A552B74B607C78B759776BD2")
	sign, err := key.Sign(rand.Reader, msg, nil)
	if err != nil {
		return
	}
	encode, err := ucapp4go.HexEncode(sign)
	if err != nil {
		return
	}
	fmt.Printf("S:%s", encode+"\n")
	ret := key.Verify(msg,sign)
	fmt.Printf("ret:%s", ret)
}
