package dhkx

import (
	"math/big"
)

type DHKey struct {
	x *big.Int
	y *big.Int
}

func (self *DHKey) Bytes() []byte {
	if self.y == nil {
		return nil
	}
	return self.y.Bytes()
}

func (self *DHKey) String() string {
	if self.y == nil {
		return ""
	}
	return self.y.String()
}

func (self *DHKey) IsPrivateKey() bool {
	return self.x != nil
}

func NewPublicKey(s []byte) *DHKey {
	key := new(DHKey)
	key.y = new(big.Int).SetBytes(s)
	return key
}
