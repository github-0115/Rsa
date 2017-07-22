package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"io/ioutil"
	"log"
	"os"
)

func RsaFile() {

	var bits int
	bits = 2048
	if err := GenRsaKey(bits); err != nil {
		log.Fatal("密钥文件生成失败！")
	}
	log.Println("密钥文件生成成功！")

}

func init() {
	var err error
	publicKey, err = ioutil.ReadFile("public.pem")
	if err != nil {
		os.Exit(-1)
	}

	privateKey, err = ioutil.ReadFile("private.pem")
	if err != nil {
		os.Exit(-1)
	}
}

func GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "私钥",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "公钥",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}
