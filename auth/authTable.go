package auth

import (
	"sync"
	"time"
)

type AuthTables struct {
	table sync.Map // key:ID, val: latestUpdateTime
}

func (this *AuthTables) Add(ID AuthID) {
	this.table.Store(ID, time.Now().UnixNano())
}

func (this *AuthTables) Del(ID AuthID) {
	this.table.Delete(ID)
}

func (this *AuthTables) Exist(ID AuthID) bool {
	_, exist := this.table.Load(ID)
	return exist
}
