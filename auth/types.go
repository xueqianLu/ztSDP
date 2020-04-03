package auth

const (
	AuthRandomLen   = 16
	AuthIdLen       = 16
	AuthCheckValLen = 32
)

type AuthID [AuthIdLen]byte

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
