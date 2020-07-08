package auth

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
)

func SM4EncryptCBC(key sm4.SM4Key, packet []byte) (encdata []byte) {
	if len(packet) == 0 {
		return
	}
	c, e := sm4.NewCipher(key)
	if e != nil {
		println("SM4DecryptCBC new cipher error", e)
		return encdata
	}
	padding := PKCS7Padding(packet, c.BlockSize())
	encdata = make([]byte, len(padding))
	for i := 0; i < len(padding)/16; i++ {
		s := i * 16
		e := (i + 1) * 16
		c.Encrypt(encdata[s:e], padding[s:e])
	}
	return encdata
}

func SM4DecryptCBC(key sm4.SM4Key, encdata []byte) (data []byte) {
	if len(encdata) == 0 || (len(encdata)%16) != 0 {
		println("SM4DecryptCBC Decrypt ", len(encdata))
		return data
	}
	c, e := sm4.NewCipher(key)
	if e != nil {
		println("SM4DecryptCBC new cipher failed,", e)
		return data
	}
	decdata := make([]byte, len(encdata))
	for i := 0; i < len(encdata)/16; i++ {
		s := i * 16
		e := (i + 1) * 16
		c.Decrypt(decdata[s:e], encdata[s:e])
	}
	data = PKCS7UnPadding(decdata)
	return data
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
