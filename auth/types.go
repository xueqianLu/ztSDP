package auth

const (
	AuthRandomLen   = 16
	AuthCheckValLen = 32
)

type AuthID [16]byte

type AuthRandom [AuthRandomLen]byte
type AuthCheckVal [AuthCheckValLen]byte

func (s *AuthCheckVal) SetBytes(data []byte) {
	copy(s[:], data[:AuthCheckValLen])
}

type AuthData struct {
	AppIdChk AuthCheckVal
	UsrIdChk AuthCheckVal
	Random   AuthRandom
}
