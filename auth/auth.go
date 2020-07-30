package auth

import (
	"bytes"
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm4"
	"sync"
)

type Authorize struct {
	SM4Key sm4.SM4Key
	table  *AuthTables
	rwMux  sync.RWMutex
}

const (
	AppID     = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	EncOffset = 16 + 32 + 32 + 16
)

var iv = []byte{0x13, 0x07, 0x1b, 0x06, 0x11, 0x0a, 0x07, 0x01, 0x01, 0x1c, 0x15, 0x00, 0x1c, 0x1b, 0x19, 0x0a}

func NewAuthorize() *Authorize {
	return &Authorize{table: &AuthTables{}}
}

func (this Authorize) CheckVal(data *AuthData) bool {
	appchk := AppidCheckVal([]byte(AppID), data.Random[:])
	if result := bytes.Compare(appchk, data.AppIdChk[:]); result != 0 {
		return false
	}
	return true
}

func (this Authorize) CheckId(data *AuthData, pid AuthID) bool {

	c := UserIdCheckVal(pid[:], iv, data.Random[:])
	if result := bytes.Compare(c, data.UsrIdChk[:]); result != 0 {
		return false
	}
	return true
}

func (this Authorize) GenerateAuthData(id AuthID, pubkey []byte) *AuthData {
	val, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		return nil
	}

	var random AuthRandom
	var appid AuthCheckVal
	var usrid AuthCheckVal
	var client_index [AuthIndexLen]byte

	copy(random[:], val.Bytes()[:AuthRandomLen])
	chk := AppidCheckVal([]byte(AppID), random[:])
	appid.SetBytes(chk)
	chk = UserIdCheckVal(id[:], iv, random[:])
	usrid.SetBytes(chk)
	for i := 0; i < AuthIndexLen/AuthRandomLen; i++ {
		for j := 0; j < AuthRandomLen; j++ {
			client_index[i*AuthRandomLen+j] = pubkey[i*AuthRandomLen+j] ^ random[j]
		}
	}

	return &AuthData{
		ClientIndex: client_index,
		Random:      random,
		AppIdChk:    appid,
		UsrIdChk:    usrid,
	}
}

func (this Authorize) EncPacket(data []byte) []byte {
	key := this.SM4Key
	encdata := SM4EncryptCBC(key[:], data[EncOffset:])

	ret := BytesCombine(data[:EncOffset], encdata)

	return ret
}

func (this Authorize) DecPacket(packet []byte) []byte {
	key := this.SM4Key
	decdata := SM4DecryptCBC(key[:], packet[EncOffset:])

	ret := BytesCombine(packet[:EncOffset], decdata)
	return ret
}
