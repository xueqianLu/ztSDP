package auth

import (
	"crypto/ecdsa"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
)

func SM4Encrypt(key sm4.SM4Key, packet []byte) (encdata []byte) {
	sm4.EncryptBlock(key, encdata, packet)
	return encdata
}

func SM4Decrypt(key sm4.SM4Key, encdata []byte) (decdata []byte) {
	sm4.DecryptBlock(key, decdata, encdata)
	return decdata
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
