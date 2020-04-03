package auth

import (
	"bytes"
	"crypto/rand"
	"sync"
)

type Authorize struct {
	table *AuthTables
	rwMux sync.RWMutex
}

var iv = []byte{0x13, 0x07, 0x1b, 0x06, 0x11, 0x0a, 0x07, 0x01, 0x01, 0x1c, 0x15, 0x00, 0x1c, 0x1b, 0x19, 0x0a}
var AppID = "AZEROTRUSTNETWORKACCESSTOANYONEL"

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
		Random:   random,
		AppIdChk: appid,
		UsrIdChk: usrid,
	}
}
