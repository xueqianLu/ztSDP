package auth

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"log"
)

var (
	sm4_iv = []byte("1234567812345678")
)

func SM4EncryptCBC(key sm4.SM4Key, packet []byte) []byte {
	block, e := sm4.NewCipher(key)
	if e != nil {
		log.Println("SM4DecryptCBC new cipher error", e)
		return nil
	}
	log.Println("SM4EncryptCBC, key:", hex.EncodeToString(key), ",iv:", sm4_iv)
	log.Println("SM4EncryptCBC, before :", hex.EncodeToString(packet))

	padding := PKCS7Padding(packet, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, []byte(sm4_iv))

	crypted := make([]byte, len(padding))
	blockMode.CryptBlocks(crypted, padding)
	log.Println("SM4EncryptCBC, after :", hex.EncodeToString(crypted))
	return crypted
}

func SM4DecryptCBC(key sm4.SM4Key, crypted []byte) []byte {
	log.Println("SM4DecryptCBC, key:", hex.EncodeToString(key), ",iv:", sm4_iv)
	if len(crypted) == 0 || (len(crypted)%16) != 0 {
		log.Println("SM4DecryptCBC Decrypt ", len(crypted))
		return nil
	}
	log.Println("SM4DecryptCBC, before :", hex.EncodeToString(crypted))
	block, e := sm4.NewCipher(key)
	if e != nil {
		println("SM4DecryptCBC new cipher failed,", e)
		return nil
	}
	blockMode := cipher.NewCBCDecrypter(block, []byte(sm4_iv))
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)

	origData = PKCS7UnPadding(origData)
	log.Println("SM4DecryptCBC, after :", hex.EncodeToString(origData))
	return origData
}

func GetSM2PubkeyFromCert(cert *sm2.Certificate) (*sm2.PublicKey, error) {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		{
			switch pub.Curve {
			case sm2.P256Sm2():
				sm2pub := &sm2.PublicKey{
					Curve: pub.Curve,
					X:     pub.X,
					Y:     pub.Y,
				}
				return sm2pub, nil
			default:
				return nil, errors.New("not P256Sm2")
			}
		}
	default:
		return nil, errors.New("not a sm2 cert")
	}
}

func PKCS7Padding(origData []byte, blockSize int) []byte {
	padding := blockSize - len(origData)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	return append(origData, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:length-unpadding]
}
