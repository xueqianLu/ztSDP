package auth

const (
	AuthSMKeyLen    = 16
	AuthRandomLen   = 16
	AuthIdLen       = 16
	AuthCheckValLen = 32
)

type AuthSMKey [AuthSMKeyLen]byte
type AuthID [AuthIdLen]byte

type AuthRandom [AuthRandomLen]byte
type AuthCheckVal [AuthCheckValLen]byte

func (s *AuthCheckVal) SetBytes(data []byte) {
	copy(s[:], data[:AuthCheckValLen])
}

type AuthData struct {
	SMKey    AuthSMKey
	AppIdChk AuthCheckVal
	UsrIdChk AuthCheckVal
	Random   AuthRandom
}
