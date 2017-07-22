package main

import (
	"flag"
	"fmt"
	tool "rsaDemo/rsa_tool"
)

var msgStr string

func init() {
	flag.StringVar(&msgStr, "msg", "Content to be encrypted", "加密解密的数据")
	flag.Parse()
}

func main() {

	fmt.Println(msgStr + "\n")
	//把数据转换成base64
	base64Str := tool.BaseEncodeToString([]byte(msgStr))
	fmt.Println("string to base64 :" + base64Str + "\n")
	//如果解密base64类型要先把数据转换
	msg := tool.BaseDecodeString(base64Str)
	if msg == nil {
		fmt.Println("base64 DecodeString err")
	}
	fmt.Println("base64 to string :" + string(msg) + "\n")

	// 解码公钥
	pubKey := tool.ParsePublicKey(tool.PublicKey)
	if pubKey == nil {
		fmt.Println("Parse PublicKey err")
	}

	// 加密数
	encryptPKCS15 := tool.EncryptPKCS1v15(pubKey, msg)
	if encryptPKCS15 == nil {
		fmt.Println("rsa EncryptPKCS1v15 err")
	}
	fmt.Println("EncryptPKCS1v15 string:" + string(encryptPKCS15) + "\n")

	encryptOAEP := tool.EncryptOAEP(pubKey, msg)
	if encryptOAEP == nil {
		fmt.Println("rsa EncryptOAEP err")
	}
	fmt.Println("EncryptOAEP string :" + string(encryptOAEP) + "\n")

	// 解析出私钥
	priKey := tool.ParsePrivateKey(tool.PrivateKey)
	if priKey == nil {
		fmt.Println("Parse PrivateKey err")
	}

	// 解密PKCS1v15加密的内容
	decryptPKCS := tool.DecryptPKCS1v15(priKey, encryptPKCS15)
	if decryptPKCS == nil {
		fmt.Println("rsa DecryptPKCS1v15 err")
	}
	fmt.Println("DecryptPKCS1v15 string:" + string(decryptPKCS) + "\n")

	// 解密RSA-OAEP方式加密后的内容
	decryptOAEP := tool.DecryptOAEP(priKey, encryptOAEP)
	if decryptOAEP == nil {
		fmt.Println("rsa DecryptOAEP err")
	}
	fmt.Println("DecryptOAEP string:" + string(decryptOAEP) + "\n")

}
