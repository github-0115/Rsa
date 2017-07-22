package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	//	"strings"
)

var (
	// 获取公钥（公钥也可以从证书中读取）
	publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZsfv1qscqYdy4vY+P4e3cAtmv
ppXQcRvrF1cB4drkv0haU24Y7m5qYtT52Kr539RdbKKdLAM6s20lWy7+5C0Dgacd
wYWd/7PeCELyEipZJL07Vro7Ate8Bfjya+wltGK9+XNUIHiumUKULW4KDx21+1NL
AUeJ6PeW+DAkmJWF6QIDAQAB
-----END PUBLIC KEY-----
`)

	// 获取私钥
	privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDZsfv1qscqYdy4vY+P4e3cAtmvppXQcRvrF1cB4drkv0haU24Y
7m5qYtT52Kr539RdbKKdLAM6s20lWy7+5C0DgacdwYWd/7PeCELyEipZJL07Vro7
Ate8Bfjya+wltGK9+XNUIHiumUKULW4KDx21+1NLAUeJ6PeW+DAkmJWF6QIDAQAB
AoGBAJlNxenTQj6OfCl9FMR2jlMJjtMrtQT9InQEE7m3m7bLHeC+MCJOhmNVBjaM
ZpthDORdxIZ6oCuOf6Z2+Dl35lntGFh5J7S34UP2BWzF1IyyQfySCNexGNHKT1G1
XKQtHmtc2gWWthEg+S6ciIyw2IGrrP2Rke81vYHExPrexf0hAkEA9Izb0MiYsMCB
/jemLJB0Lb3Y/B8xjGjQFFBQT7bmwBVjvZWZVpnMnXi9sWGdgUpxsCuAIROXjZ40
IRZ2C9EouwJBAOPjPvV8Sgw4vaseOqlJvSq/C/pIFx6RVznDGlc8bRg7SgTPpjHG
4G+M3mVgpCX1a/EU1mB+fhiJ2LAZ/pTtY6sCQGaW9NwIWu3DRIVGCSMm0mYh/3X9
DAcwLSJoctiODQ1Fq9rreDE5QfpJnaJdJfsIJNtX1F+L3YceeBXtW0Ynz2MCQBI8
9KP274Is5FkWkUFNKnuKUK4WKOuEXEO+LpR+vIhs7k6WQ8nGDd4/mujoJBr5mkrw
DPwqA3N5TMNDQVGv8gMCQQCaKGJgWYgvo3/milFfImbp+m7/Y3vCptarldXrYQWO
AQjxwc71ZGBFDITYvdgJM1MTqc8xQek1FXn1vfpy2c6O
-----END RSA PRIVATE KEY-----
`)
)

var msgStr string

func init() {
	flag.StringVar(&msgStr, "msg", "Content to be encrypted", "加密解密的数据")
	flag.Parse()
}

func main() {

	fmt.Println(msgStr + "\n")
	//把数据转换成base64
	base64Str := BaseEncodeToString([]byte(msgStr))
	fmt.Println("string to base64 :" + base64Str + "\n")
	//如果解密base64类型要先把数据转换
	msg := BaseDecodeString(base64Str)
	if msg == nil {
		fmt.Println("base64 DecodeString err")
	}
	fmt.Println("base64 to string :" + string(msg) + "\n")

	// 解码公钥
	pubKey := ParsePublicKey(publicKey)
	if pubKey == nil {
		fmt.Println("Parse PublicKey err")
	}

	// 加密数
	encryptPKCS15 := EncryptPKCS1v15(pubKey, msg)
	if encryptPKCS15 == nil {
		fmt.Println("rsa EncryptPKCS1v15 err")
	}
	fmt.Println("EncryptPKCS1v15 string:" + string(encryptPKCS15) + "\n")

	encryptOAEP := EncryptOAEP(pubKey, msg)
	if encryptOAEP == nil {
		fmt.Println("rsa EncryptOAEP err")
	}
	fmt.Println("EncryptOAEP string :" + string(encryptOAEP) + "\n")

	// 解析出私钥
	priKey := ParsePrivateKey(privateKey)
	if priKey == nil {
		fmt.Println("Parse PrivateKey err")
	}

	// 解密PKCS1v15加密的内容
	decryptPKCS := DecryptPKCS1v15(priKey, encryptPKCS15)
	if decryptPKCS == nil {
		fmt.Println("rsa DecryptPKCS1v15 err")
	}
	fmt.Println("DecryptPKCS1v15 string:" + string(decryptPKCS) + "\n")

	// 解密RSA-OAEP方式加密后的内容
	decryptOAEP := DecryptOAEP(priKey, encryptOAEP)
	if decryptOAEP == nil {
		fmt.Println("rsa DecryptOAEP err")
	}
	fmt.Println("DecryptOAEP string:" + string(decryptOAEP) + "\n")

}

/**
*	生成base64String
*	@parmar:1、 data []byte 需要生成的内容
*	@return:1、 string
 */
func BaseEncodeToString(data []byte) string {
	str := base64.StdEncoding.EncodeToString(data)

	return str
}

/**
*	解析base64String
*	@parmar:1、 base64Str string 需要解析的内容
*	@return:1、 []byte
 */
func BaseDecodeString(base64Str string) []byte {
	data, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		fmt.Println("base64 DecodeString err:%s", err.Error())
		return nil
	}
	return data
}

/**
*	解析公钥
*	@parmar:1、 publicKeyData []byte 需要解密公钥
*
*	@return:1、 *rsa.PublicKey
 */
func ParsePublicKey(publicKeyData []byte) *rsa.PublicKey {

	pubBlock, _ := pem.Decode(publicKeyData)

	pubKeyValue, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		fmt.Println("Parse PublicKey err:%s", err.Error())
		return nil
	}
	pubKey := pubKeyValue.(*rsa.PublicKey)

	return pubKey
}

/**
*	解析私钥
*	@parmar:1、 privateKeyData []byte 需要解密私钥
*
*	@return:1、 *rsa.PrivateKey
 */
func ParsePrivateKey(privateKeyData []byte) *rsa.PrivateKey {

	priBlock, _ := pem.Decode(privateKeyData)

	priKey, err := x509.ParsePKCS1PrivateKey(priBlock.Bytes)
	if err != nil {
		fmt.Println("Parse PrivateKey err:%s", err.Error())
		return nil
	}

	return priKey
}

/**
*	PKCS1v15加密
*	注意：用这个函数加密纯文本是很危险的，尽量使用下面的EncryptOAEP方法
*	@parmar:1、 priKey *rsa.PublicKey 加密公钥
*			2、 msg []byte 要加密内容
*
*	@return:1、 []byte 加密后的数据
 */
func EncryptPKCS1v15(pubKey *rsa.PublicKey, msg []byte) []byte {

	encryptPKCS15, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, msg)
	if err != nil {
		fmt.Println("rsa EncryptPKCS1v15 err:%s", err.Error())
		return nil
	}

	return encryptPKCS15
}

/**
*	解密PKCS1v15加密的内容
*	@parmar:1、 priKey *rsa.PrivateKey 解密私钥
*			2、 ciphertext []byte 要解密内容
*
*	@return:1、 []byte 解密后的数据
 */
func DecryptPKCS1v15(priKey *rsa.PrivateKey, ciphertext []byte) []byte {

	decryptPKCS, err := rsa.DecryptPKCS1v15(rand.Reader, priKey, ciphertext)
	if err != nil {
		fmt.Println("rsa DecryptPKCS1v15 err:%s", err.Error())
		return nil
	}

	return decryptPKCS
}

/**
*	EncryptOAEP加密
*	@parmar:1、 priKey *rsa.PublicKey 加密公钥
*			2、 msg []byte 要加密内容
*
*	@return:1、 []byte 加密后的数据
 */
func EncryptOAEP(pubKey *rsa.PublicKey, msg []byte) []byte {

	encryptOAEP, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pubKey, msg, nil)
	if err != nil {
		fmt.Println("rsa EncryptOAEP err:%s", err.Error())
		return nil
	}

	return encryptOAEP
}

/**
*	解密RSA-OAEP方式加密后的内容
*	@parmar:1、 priKey *rsa.PrivateKey 解密私钥
*			2、 ciphertext []byte 要解密内容
*
*	@return:1、 []byte 解密后的数据
 */
func DecryptOAEP(priKey *rsa.PrivateKey, ciphertext []byte) []byte {

	decryptOAEP, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priKey, ciphertext, nil)
	if err != nil {
		fmt.Println("rsa DecryptOAEP err:%s", err.Error())
		return nil
	}

	return decryptOAEP
}
