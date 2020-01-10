package auth

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
)

type Authorize struct {
	table *AuthTables
	rwMux sync.RWMutex
}

var iv = []byte{0x13, 0x07, 0x1b, 0x06, 0x11, 0x0a, 0x07, 0x01, 0x01, 0x1c, 0x15, 0x00, 0x1c, 0x1b, 0x19, 0x0a}

func NewAuthorize() *Authorize {
	return &Authorize{table: &AuthTables{}}
}

func (this Authorize) SetId(id AuthID) {
	this.rwMux.Lock()
	defer this.rwMux.Unlock()
}

func (this Authorize) AddId(id AuthID) {
	this.table.Add(id)
}

func (this Authorize) DelId(id AuthID) {
	this.table.Del(id)
}

func (this Authorize) ValidId(id AuthID) bool {
	return this.table.Exist(id)
}

func (this Authorize) CheckVal(data *AuthData) bool {
	var lid AuthID
	var lcheckVal AuthCheckVal
	for i := 0; i < AuthDataFieldLen; i++ {
		lid[i] = data.Id[i] ^ data.Random[i]
	}
	for i := 0; i < AuthDataFieldLen; i++ {
		lcheckVal[i] = (lid[i] ^ iv[i]) ^ data.Random[i]
	}
	if result := bytes.Compare(lcheckVal[:], data.Checkval[:]); result != 0 {
		return false
	}

	return true
}

func (this Authorize) CheckId(data *AuthData, pid AuthID) bool {
	var lid AuthID
	for i := 0; i < AuthDataFieldLen; i++ {
		lid[i] = data.Id[i] ^ data.Random[i]
	}
	if result := bytes.Compare(lid[:], pid[:]); result != 0 {
		return false
	}
	return true
}

func (this Authorize) GenerateAuthData(id AuthID) *AuthData {
	var reader io.Reader
	val, err := rand.Prime(reader, 128)
	if err != nil {
		return nil
	}

	var random AuthRandom
	var aid AuthID
	var checkVal AuthCheckVal

	copy(random[:], val.Bytes()[:AuthDataFieldLen])
	for i := 0; i < AuthDataFieldLen; i++ {
		checkVal[i] = (id[i] ^ iv[i]) ^ random[i]
		aid[i] = id[i] ^ random[i]
	}
	return &AuthData{
		Id:       aid,
		Random:   random,
		Checkval: checkVal,
	}
}
