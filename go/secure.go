package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
  "unsafe"
)


func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}


func main() {
	password := "trololo"
    data := "zookeeper    | 2019-03-17 18:01:43,254 [myid:] - INFO  [ProcessThread(sid:0 cport:2181)::PrepRequestProcessor@486] - Processed session termination for sessionid: 0x1698cd0dd800001"

	fmt.Println("Starting the application...")
	ciphertext := encrypt([]byte(data), password)
	fmt.Printf("Encrypted: %x\n", ciphertext)
	fmt.Printf("size of Encrypted string: %s\n", unsafe.Sizeof(ciphertext))
	plaintext := decrypt(ciphertext, password)
	fmt.Printf("Decrypted: %s\n", plaintext)
	fmt.Printf("size of Decrypted string: %s\n", unsafe.Sizeof(plaintext))

}

