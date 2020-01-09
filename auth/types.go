package auth

const (
	AuthDataFieldLen = 16
)

type AuthID [AuthDataFieldLen]byte
type AuthRandom [AuthDataFieldLen]byte
type AuthCheckVal [AuthDataFieldLen]byte

type AuthData struct {
	Id       AuthID
	Random   AuthRandom
	Checkval AuthCheckVal
}
