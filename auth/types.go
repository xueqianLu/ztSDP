package auth

const (
	AuthIndexLen    = 32
	AuthRandomLen   = 16
	AuthIdLen       = 16
	AuthCheckValLen = 32
)

type AuthIndex [AuthIndexLen]byte
type AuthID [AuthIdLen]byte

type AuthRandom [AuthRandomLen]byte
type AuthCheckVal [AuthCheckValLen]byte

func (s *AuthCheckVal) SetBytes(data []byte) {
	copy(s[:], data[:AuthCheckValLen])
}

type AuthData struct {
	ClientIndex AuthIndex
	AppIdChk    AuthCheckVal
	UsrIdChk    AuthCheckVal
	Random      AuthRandom
}
