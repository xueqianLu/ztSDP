package auth

import (
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

func (this Authorize) CheckId(id AuthID) bool {
	return this.table.Exist(id)
}

func (this Authorize) CheckVal(data *AuthData) bool {
	//Todo:Add checkval
	return true
}

func (this Authorize) GenerateAuthData(id AuthID) *AuthData {
	var reader io.Reader
	val, err := rand.Prime(reader, 128)
	if err != nil {
		return nil
	}

	//Todo:Add checkval generate
	//Todo:Add id generate
	var random AuthRandom
	copy(random[:], val.Bytes()[:AuthDataFieldLen])
	return &AuthData{
		Id:       id,
		Random:   random,
		Checkval: *new(AuthCheckVal),
	}
}
