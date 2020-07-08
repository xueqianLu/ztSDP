package auth

import (
	"bytes"
	"crypto/rand"
	"github.com/tjfoc/gmsm/sm4"
	"sync"
)

type Authorize struct {
	SM4Key AuthSMKey
	table  *AuthTables
	rwMux  sync.RWMutex
}

const (
	AppID     = "AZEROTRUSTNETWORKACCESSTOANYONEL"
	EncOffset = 16 + 32 + 32 + 16
)

var iv = []byte{0x13, 0x07, 0x1b, 0x06, 0x11, 0x0a, 0x07, 0x01, 0x01, 0x1c, 0x15, 0x00, 0x1c, 0x1b, 0x19, 0x0a}

func NewAuthorizeWithKey(SM4Key []byte) *Authorize {
	key := AuthSMKey{}
	copy(key[:], SM4Key[:AuthSMKeyLen])
	return &Authorize{table: &AuthTables{}, SM4Key: key}
}

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

func (this Authorize) GenerateAuthData(id AuthID) *AuthData {
	val, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		return nil
	}

	var random AuthRandom
	var appid AuthCheckVal
	var usrid AuthCheckVal

	copy(random[:], val.Bytes()[:AuthRandomLen])
	chk := AppidCheckVal([]byte(AppID), random[:])
	appid.SetBytes(chk)
	chk = UserIdCheckVal(id[:], iv, random[:])
	usrid.SetBytes(chk)

	return &AuthData{
		SMKey:    this.SM4Key,
		Random:   random,
		AppIdChk: appid,
		UsrIdChk: usrid,
	}
}

func (this Authorize) EncPacket(data []byte) []byte {
	key := sm4.SM4Key{}
	key = BytesCombine(key, data[:AuthSMKeyLen])
	encdata := SM4EncryptCBC(key, data[EncOffset:])

	ret := BytesCombine(data[:EncOffset], encdata)

	return ret
}

func (this Authorize) DecPacket(packet []byte) []byte {
	key := sm4.SM4Key{}
	key = BytesCombine(key, packet[:AuthSMKeyLen])

	decdata := SM4DecryptCBC(key, packet[EncOffset:])

	ret := BytesCombine(packet[:EncOffset], decdata)
	return ret
}
